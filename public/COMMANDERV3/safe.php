<?php
/**
 * COMMANDER V11 - White Page Interna ("Industry Safe Page")
 *
 * Pagina segura generica servida pelo proprio COMMANDER. Substitui a necessidade
 * de hospedar uma white externa: e polida, parece um negocio legitimo (e-commerce
 * / consultoria) e tem um formulario de captura de lead que funciona de verdade.
 *
 * Como usar:
 *  - Na campanha, escolha "White Page: Interna". O sistema aponta a white_url
 *    para este arquivo automaticamente (safe.php?c=SLUG).
 *  - O nome da marca no topo/rodape e SEMPRE derivado do DOMINIO da campanha
 *    (ex.: loja14.estoremtkkm.shop -> "Estoremtkkm"). Pode sobrescrever com
 *    &brand=Nome.
 *
 * IMPORTANTE (compatibilidade com o PROXY):
 *  Quando servida via proxy, o tracker injeta um <base href="painel/"> e
 *  intercepta cliques/submits. Por isso esta pagina foi feita IMUNE ao proxy:
 *   - Todos os links usam javascript:void(0) (o <base> nao afeta e o proxy
 *     ignora), abrindo modais 100% client-side, SEM navegar. Assim o dominio do
 *     anuncio nunca muda ao clicar/fechar (link morto ou troca de dominio sao
 *     motivos comuns de suspensao).
 *   - Nao ha tag <form> (o proxy reescreve action de <form>). O envio do lead e
 *     feito por fetch. Em modo proxy, o POST vai para a MESMA origem via ?_nav=,
 *     e o tracker repassa ao safe.php no servidor (sem mixed content/SSL).
 */

define('COMMANDER_ACCESS', true);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';

if (!defined('DATA_DIR')) {
    define('DATA_DIR', __DIR__ . '/data/');
}
$LEADS_FILE = DATA_DIR . 'leads.json';

// ---------------------------------------------------------------------------
// Identifica a campanha (opcional) para derivar marca e associar o lead
// ---------------------------------------------------------------------------
$slug = isset($_GET['c']) ? preg_replace('/[^a-zA-Z0-9_\-]/', '', $_GET['c']) : '';
$campaign = null;
if ($slug !== '' && function_exists('getCampaignBySlug')) {
    $campaign = getCampaignBySlug($slug);
}

/**
 * Deriva um nome de marca apresentavel a partir de um dominio/host.
 * INCLUI o subdominio para que cada subdominio pareca um site distinto:
 *   loja14.estoremtkkm.shop -> "Loja14 Estoremtkkm"
 *   loja15.estoremtkkm.shop -> "Loja15 Estoremtkkm"
 *   estoremtkkm.shop        -> "Estoremtkkm"
 *   modawearfemttkshop.com  -> "Modawearfemttkshop"
 * Assim, ao trocar o subdominio, o nome exibido/favicon/titulo mudam junto.
 */
function safeBrandFromHost($host) {
    $host = preg_replace('#^https?://#i', '', (string)$host);
    $host = preg_replace('#/.*$#', '', $host);      // remove path
    $host = preg_replace('#:\d+$#', '', $host);     // remove porta
    $host = preg_replace('#^www\.#i', '', $host);
    $host = strtolower(trim($host));
    if ($host === '') return '';
    $parts = array_values(array_filter(explode('.', $host), function ($p) { return $p !== ''; }));
    $n = count($parts);
    if ($n >= 2) {
        // SLD (dominio registravel, sem TLD) + todos os subdominios antes dele.
        $sld  = $parts[$n - 2];                       // ex.: estoremtkkm
        $subs = array_slice($parts, 0, $n - 2);       // ex.: [loja14]
        $labels = array_merge($subs, [$sld]);         // ex.: [loja14, estoremtkkm]
    } else {
        $labels = [$parts[0] ?? $host];
    }
    // Limpa cada label e monta o nome em Title Case: "Loja14 Estoremtkkm"
    $clean = array();
    foreach ($labels as $lb) {
        $lb = trim(preg_replace('/[^a-zA-Z0-9]/', ' ', $lb));
        if ($lb !== '') $clean[] = ucwords($lb);
    }
    return implode(' ', $clean);
}

// Marca: &brand= > HOST realmente visitado (reflete o subdominio) > DOMINIO da
// campanha > nome da campanha. Priorizamos o host visitado para que loja14 e
// loja15 exibam nomes diferentes; o IP do painel (teste direto) nao e um dominio
// valido, entao cai para o dominio da campanha.
$brand = '';
if (!empty($_GET['brand'])) {
    $brand = trim(preg_replace('/[^\p{L}\p{N}\s\.\-&]/u', '', $_GET['brand']));
}
$visitedHost = preg_replace('#:\d+$#', '', $_SERVER['HTTP_HOST'] ?? '');
$hostIsDomain = ($visitedHost !== '' && strpos($visitedHost, '.') !== false
    && !preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $visitedHost)); // exclui IPv4
if ($brand === '' && $hostIsDomain) {
    $brand = safeBrandFromHost($visitedHost);
}
if ($brand === '' && $campaign && !empty($campaign['domain'])) {
    $brand = safeBrandFromHost($campaign['domain']);
}
if ($brand === '' && $campaign && !empty($campaign['name'])) {
    $brand = ucwords(strtolower($campaign['name']));
}
if ($brand === '') $brand = 'Shop';

// ---------------------------------------------------------------------------
// Submissao do formulario de lead (POST via fetch)
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (($_POST['action'] ?? '') === 'lead')) {
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');

    $email = trim($_POST['email'] ?? '');
    $notes = trim($_POST['notes'] ?? '');

    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'invalid_email']);
        exit;
    }

    $lead = [
        'id'          => bin2hex(random_bytes(8)),
        'campaign'    => $slug,
        'campaign_id' => $campaign['id'] ?? '',
        'email'       => mb_substr($email, 0, 200),
        'notes'       => mb_substr($notes, 0, 1000),
        'ip'          => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? ($_SERVER['REMOTE_ADDR'] ?? ''),
        'ua'          => mb_substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 300),
        'created_at'  => date('Y-m-d H:i:s'),
    ];

    $leads = readJsonFile($LEADS_FILE, []);
    if (!is_array($leads)) $leads = [];
    $leads[] = $lead;
    // Mantem no maximo 5000 leads para nao pesar
    if (count($leads) > 5000) {
        $leads = array_slice($leads, -5000);
    }
    writeJsonFile($LEADS_FILE, $leads);

    echo json_encode(['ok' => true]);
    exit;
}

// URL ABSOLUTA do safe.php NO PAINEL (host/porta/scheme reais desta requisicao).
// - Modo direto (teste): o navegador ja esta no painel, entao posta aqui mesmo.
// - Modo proxy: o navegador esta no dominio do anuncio; o POST vai para a mesma
//   origem via ?_nav=<base64 desta URL> e o tracker repassa para ca no SERVIDOR
//   (curl), evitando mixed content / erro de certificado.
// Usamos o HTTPS REAL desta conexao (nao o X-Forwarded-Proto) para o curl do
// proxy conseguir alcancar o painel no mesmo scheme em que ele responde.
$panelScheme = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') ? 'https' : 'http';
$panelHost   = $_SERVER['HTTP_HOST'] ?? '';
$panelPath   = strtok($_SERVER['REQUEST_URI'] ?? '/safe.php', '?');
$panelSafeUrl = $panelScheme . '://' . $panelHost . $panelPath . '?c=' . rawurlencode($slug);

$year = date('Y');
$brandEsc = htmlspecialchars($brand, ENT_QUOTES, 'UTF-8');

// Favicon dinamico: inicial da marca sobre um quadrado arredondado com o
// gradiente de destaque. Muda junto com o dominio/subdominio, reforcando que
// cada subdominio e um "site" diferente. Entregue como data-URI (sem arquivo).
$faviconInitial = strtoupper(mb_substr(preg_replace('/[^A-Za-z0-9]/', '', $brand) ?: 'S', 0, 1));
$faviconSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">'
    . '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
    . '<stop offset="0" stop-color="#2dd4bf"/><stop offset="1" stop-color="#38bdf8"/>'
    . '</linearGradient></defs>'
    . '<rect width="64" height="64" rx="14" fill="url(#g)"/>'
    . '<text x="50%" y="52%" dominant-baseline="central" text-anchor="middle" '
    . 'font-family="Segoe UI,Helvetica,Arial,sans-serif" font-size="36" font-weight="700" fill="#04121a">'
    . htmlspecialchars($faviconInitial, ENT_QUOTES, 'UTF-8') . '</text></svg>';
$faviconHref = 'data:image/svg+xml;base64,' . base64_encode($faviconSvg);
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="<?php echo $brandEsc; ?> — curated marketplace with authentic products, fast shipping and easy returns.">
<link rel="icon" type="image/svg+xml" href="<?php echo $faviconHref; ?>">
<!-- Marca para o proxy do tracker: pagina self-contained, servir INTACTA
     (sem tag <base>, sem reescrita de links/scripts). Evita mixed content
     e troca de dominio ao clicar. -->
<meta name="x-commander-safe" content="1">
<title><?php echo $brandEsc; ?> — Curated Picks</title>
<style>
  :root{
    --bg:#0a141f; --bg-2:#0d1a28; --card:#0f1e2e; --line:#1c2f42;
    --text:#e8eef5; --muted:#8ba0b5; --accent:#2dd4bf; --accent-2:#38bdf8;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    background:radial-gradient(1200px 600px at 50% -10%, #10263a 0%, var(--bg) 55%);
    color:var(--text); line-height:1.6; min-height:100vh; padding:24px 16px;
  }
  .wrap{max-width:920px;margin:0 auto}
  .brand-chip{
    display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);
    background:var(--bg-2);color:var(--text);font-weight:700;letter-spacing:.12em;
    text-transform:uppercase;font-size:12px;padding:8px 16px;border-radius:999px;margin:8px auto 28px;
    cursor:pointer;text-decoration:none
  }
  .head{text-align:center;margin-bottom:28px}
  .eyebrow{color:var(--accent);font-weight:700;letter-spacing:.18em;text-transform:uppercase;font-size:12px;margin-bottom:14px}
  h1{font-size:clamp(28px,5vw,44px);line-height:1.15;letter-spacing:-.02em;margin-bottom:12px}
  .sub{color:var(--muted);font-size:clamp(15px,2.2vw,18px);max-width:640px;margin:0 auto}
  .stats{display:flex;gap:14px;justify-content:center;flex-wrap:wrap;margin:28px 0}
  .stat{flex:1 1 180px;max-width:230px;border:1px solid var(--line);background:var(--card);border-radius:14px;padding:20px;text-align:center}
  .stat b{display:block;font-size:26px;letter-spacing:-.02em}
  .stat span{color:var(--muted);font-size:13px}
  .panel{border:1px solid var(--line);background:var(--card);border-radius:18px;padding:26px;margin:8px 0 34px}
  label{display:block;font-weight:700;margin:14px 0 8px}
  input,textarea{
    width:100%;background:var(--bg-2);border:1px solid var(--line);border-radius:12px;
    color:var(--text);padding:14px 16px;font-size:15px;font-family:inherit;outline:none
  }
  input:focus,textarea:focus{border-color:var(--accent)}
  textarea{min-height:130px;resize:vertical}
  .btn{
    width:100%;margin-top:20px;border:0;border-radius:12px;padding:16px;cursor:pointer;
    font-size:16px;font-weight:800;color:#04121a;
    background:linear-gradient(90deg,var(--accent),var(--accent-2))
  }
  .btn:disabled{opacity:.6;cursor:default}
  .done{text-align:center;padding:26px 10px}
  .done .ok{width:64px;height:64px;border-radius:50%;background:var(--accent);color:#04121a;
    display:flex;align-items:center;justify-content:center;font-size:30px;margin:0 auto 16px}
  .done h2{margin-bottom:8px}
  .done p{color:var(--muted)}
  footer{border-top:1px solid var(--line);padding-top:26px;margin-top:10px;
    display:grid;grid-template-columns:1.4fr 1fr 1fr;gap:24px}
  footer h4{font-size:15px;margin-bottom:12px}
  footer .cols-title{color:var(--muted);text-transform:uppercase;letter-spacing:.12em;font-size:11px;margin-bottom:12px}
  footer .flink{color:var(--muted);text-decoration:none;display:block;font-size:14px;margin-bottom:8px;cursor:pointer}
  footer .flink:hover{color:var(--text)}
  .legal{margin-top:10px;display:flex;flex-wrap:wrap;gap:16px}
  .legal .flink{display:inline;margin:0;font-size:13px}
  footer ul{list-style:none}
  .pill{display:inline-block;border:1px solid var(--line);color:var(--muted);font-size:11px;
    letter-spacing:.06em;text-transform:uppercase;padding:6px 12px;border-radius:999px;margin:4px 8px 0 0;
    cursor:pointer;text-decoration:none}
  .pill:hover{color:var(--text)}
  .copy{grid-column:1/-1;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:18px;margin-top:6px}
  /* Modal */
  .modal-ov{position:fixed;inset:0;background:rgba(2,8,15,.7);display:none;align-items:center;justify-content:center;padding:20px;z-index:50}
  .modal-ov.open{display:flex}
  .modal{background:var(--card);border:1px solid var(--line);border-radius:16px;max-width:560px;width:100%;max-height:80vh;overflow:auto;padding:26px}
  .modal h3{margin-bottom:12px}
  .modal p{color:var(--muted);font-size:14px;margin-bottom:12px}
  .modal .x{float:right;border:1px solid var(--line);background:var(--bg-2);color:var(--muted);
    width:34px;height:34px;border-radius:10px;cursor:pointer;font-size:16px}
  @media(max-width:640px){footer{grid-template-columns:1fr 1fr}.copy{grid-column:1/-1}}
</style>
</head>
<body>
  <div class="wrap">
    <div style="text-align:center"><span class="brand-chip" role="button" tabindex="0" data-modal="home"><?php echo strtoupper($brandEsc); ?></span></div>

    <div class="head">
      <div class="eyebrow">Limited time · Spots available</div>
      <h1>Curated Picks · Act Now</h1>
      <p class="sub">Leave your contact info — a dedicated advisor will reach out proactively.</p>
    </div>

    <div class="stats">
      <div class="stat"><b>10K+</b><span>Authentic sourcing</span></div>
      <div class="stat"><b>98%</b><span>Fast shipping</span></div>
      <div class="stat"><b>24/7</b><span>Easy returns</span></div>
    </div>

    <div class="panel">
      <!-- Sem <form>: o proxy reescreve action de <form>. Enviamos por fetch. -->
      <div id="lead-form">
        <label for="email">Your email</label>
        <input type="email" id="email" name="email" placeholder="name@example.com" autocomplete="email" required>
        <label for="notes">Additional notes (optional)</label>
        <textarea id="notes" name="notes" placeholder="Tell us what you're looking for"></textarea>
        <button class="btn" type="button" id="submit-btn">Submit</button>
      </div>
      <div class="done" id="done" style="display:none">
        <div class="ok">&#10003;</div>
        <h2>Submitted</h2>
        <p>We received your info and will get back to you shortly.</p>
      </div>
    </div>

    <footer>
      <div>
        <h4><?php echo $brandEsc; ?></h4>
        <p style="color:var(--muted);font-size:14px">Authentic sourcing · Fast shipping · Easy returns · Priority support</p>
        <div style="margin-top:12px">
          <span class="pill" role="button" tabindex="0" data-modal="shop">Shop direct</span><span class="pill" role="button" tabindex="0" data-modal="freeship">Free ship</span>
        </div>
      </div>
      <div>
        <div class="cols-title">Services</div>
        <ul>
          <li><span class="flink" role="button" tabindex="0" data-modal="deals">Deals</span></li>
          <li><span class="flink" role="button" tabindex="0" data-modal="arrivals">New arrivals</span></li>
          <li><span class="flink" role="button" tabindex="0" data-modal="shipping">Shipping info</span></li>
          <li><span class="flink" role="button" tabindex="0" data-modal="member">Member perks</span></li>
        </ul>
      </div>
      <div>
        <div class="cols-title">Support</div>
        <ul>
          <li><span class="flink" role="button" tabindex="0" data-modal="returns">Returns policy</span></li>
          <li><span class="flink" role="button" tabindex="0" data-modal="authenticity">Authenticity check</span></li>
          <li><span class="flink" role="button" tabindex="0" data-modal="aftersales">After-sales</span></li>
          <li><span class="flink" role="button" tabindex="0" data-modal="partnerships">Partnerships</span></li>
        </ul>
      </div>
      <div class="copy">
        Major payment methods accepted · Track orders via email &copy; <?php echo $year; ?> <?php echo $brandEsc; ?>. All rights reserved.
        <div class="legal">
          <span class="flink" role="button" tabindex="0" data-modal="privacy">Privacy policy</span>
          <span class="flink" role="button" tabindex="0" data-modal="terms">Terms of service</span>
          <span class="flink" role="button" tabindex="0" data-modal="contact">Contact</span>
        </div>
      </div>
    </footer>
  </div>

  <div class="modal-ov" id="modal-ov">
    <div class="modal">
      <button class="x" id="modal-x" type="button" aria-label="Close">&times;</button>
      <h3 id="modal-title"></h3>
      <div id="modal-body"></div>
    </div>
  </div>

<script>
(function(){
  var BRAND = <?php echo json_encode($brand); ?>;
  var PANEL_HOST = <?php echo json_encode($panelHost); ?>;
  var PANEL_SAFE = <?php echo json_encode($panelSafeUrl); ?>;

  // ---- Envio do lead (best-effort; sempre confirma, igual concorrente) ----
  // Modo direto: POST direto no safe.php (mesma origem = painel).
  // Modo proxy: POST na MESMA origem (dominio do anuncio) via ?_nav=<safe url>,
  // e o tracker repassa ao safe.php no servidor (sem mixed content).
  var done = document.getElementById('done');
  var wrap = document.getElementById('lead-form');
  var btn  = document.getElementById('submit-btn');

  function submitLead(){
    var email = document.getElementById('email').value.trim();
    var notes = document.getElementById('notes').value.trim();
    if(!email){ document.getElementById('email').focus(); return; }
    btn.disabled = true; btn.textContent = 'Sending...';

    var isDirect = (location.host === PANEL_HOST);
    var url = isDirect ? PANEL_SAFE : (location.origin + '/?_nav=' + btoa(PANEL_SAFE));

    var body = new URLSearchParams();
    body.set('action','lead'); body.set('email',email); body.set('notes',notes);

    fetch(url, {
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:body.toString(),
      credentials:'omit'
    })
    .then(function(r){ return r.text(); })
    .then(function(){ finish(); })
    .catch(function(){ finish(); }); // best-effort: sempre confirma
  }
  function finish(){ wrap.style.display='none'; done.style.display='block'; }
  btn.addEventListener('click', submitLead);
  // Enter no campo de email tambem envia
  document.getElementById('email').addEventListener('keydown', function(e){
    if(e.key === 'Enter'){ e.preventDefault(); submitLead(); }
  });

  // ---- Modais dos links (conteudo generico, porem funcional/legitimo) ----
  var CONTENT = {
    home:        ['Welcome to ' + BRAND, '<p>' + BRAND + ' is a curated marketplace. Leave your contact details and a dedicated advisor will help you find authentic products with fast shipping and easy returns.</p>'],
    deals:       ['Deals', '<p>Seasonal deals are refreshed every week. Submit your email above to receive our current promotions and member-only discounts.</p>'],
    arrivals:    ['New arrivals', '<p>New selections are added regularly. Our advisors can notify you when items in your area of interest become available.</p>'],
    shipping:    ['Shipping info', '<p>Orders are processed within 24 hours and shipped with tracking. Estimated delivery is 5-9 business days depending on destination.</p>'],
    member:      ['Member perks', '<p>Members get early access to new arrivals, priority support and free shipping on qualifying orders.</p>'],
    returns:     ['Returns policy', '<p>Not satisfied? Request a return within 30 days of delivery for a full refund or exchange. Items must be unused and in original condition.</p>'],
    authenticity:['Authenticity check', '<p>Every item is verified for authenticity before shipping. A certificate of authenticity is available on request.</p>'],
    aftersales:  ['After-sales', '<p>Our after-sales team is available 24/7 to help with orders, exchanges and any questions. Reach us by email.</p>'],
    partnerships:['Partnerships', '<p>Interested in partnering with ' + BRAND + '? Submit your email above and our partnerships team will contact you.</p>'],
    shop:        ['Shop direct', '<p>Buy directly through ' + BRAND + ' with secure checkout and buyer protection on every order.</p>'],
    freeship:    ['Free shipping', '<p>Free standard shipping is available on qualifying orders. Details are confirmed at checkout.</p>'],
    privacy:     ['Privacy policy', '<p>' + BRAND + ' respects your privacy. We only collect the contact details you provide (such as your email) to respond to your request and share relevant offers. We never sell your data to third parties.</p><p>You can request access to or deletion of your data at any time by contacting us. We use industry-standard measures to protect your information.</p>'],
    terms:       ['Terms of service', '<p>By using this site you agree to browse and submit your contact details for the purpose of receiving product recommendations and offers from ' + BRAND + '.</p><p>All content is provided as-is. Prices, availability and promotions may change without notice. Orders are subject to verification and our returns and shipping policies.</p>'],
    contact:     ['Contact', '<p>Questions about an order or our products? Leave your email above and a dedicated advisor from ' + BRAND + ' will reach out to you directly, usually within one business day.</p>']
  };
  var ov = document.getElementById('modal-ov');
  var mt = document.getElementById('modal-title');
  var mb = document.getElementById('modal-body');
  function openModal(key){
    var c = CONTENT[key] || CONTENT.home;
    mt.textContent = c[0]; mb.innerHTML = c[1];
    ov.classList.add('open');
  }
  function closeModal(){ ov.classList.remove('open'); }
  // Usa capture=true para rodar ANTES do interceptador de cliques do proxy.
  document.querySelectorAll('[data-modal]').forEach(function(el){
    el.addEventListener('click', function(e){ e.preventDefault(); e.stopPropagation(); openModal(el.getAttribute('data-modal')); }, true);
    // Acessibilidade: Enter/Espaco abrem o modal (spans com role=button)
    el.addEventListener('keydown', function(e){
      if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); e.stopPropagation(); openModal(el.getAttribute('data-modal')); }
    }, true);
  });
  document.getElementById('modal-x').addEventListener('click', function(e){ e.preventDefault(); e.stopPropagation(); closeModal(); }, true);
  ov.addEventListener('click', function(e){ if(e.target === ov){ e.stopPropagation(); closeModal(); } }, true);
})();
</script>
</body>
</html>
