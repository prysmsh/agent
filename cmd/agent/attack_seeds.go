package main

// attackSeed represents an OWASP-derived request fingerprint pattern used to
// seed the WAF vector store with known-bad traffic signatures.
type attackSeed struct {
	Pattern    string
	ThreatType string
}

// owasp2025Seeds contains ~45 fingerprints covering the major OWASP attack
// categories. These are loaded once at startup to populate the edge_attacks
// vector collection so the AI WAF has a baseline of known threats.
var owasp2025Seeds = []attackSeed{
	// SQL Injection
	{Pattern: "GET /search ua:curl q:q len:empty", ThreatType: "sqli"},
	{Pattern: "POST /api/users ct:application/x-www-form-urlencoded ua:sqlmap len:small", ThreatType: "sqli"},
	{Pattern: "GET /products ua:sqlmap q:id len:empty", ThreatType: "sqli"},
	{Pattern: "POST /login ct:application/json ua:python-requests len:small", ThreatType: "sqli"},
	{Pattern: "GET /user ua:go-http-client q:id,sort len:empty", ThreatType: "sqli"},
	{Pattern: "GET /api/items ua:curl q:filter,limit len:empty", ThreatType: "sqli"},

	// XSS
	{Pattern: "GET /comment ua:firefox q:body,redirect len:empty", ThreatType: "xss"},
	{Pattern: "POST /post ct:application/x-www-form-urlencoded ua:chrome len:small", ThreatType: "xss"},
	{Pattern: "GET /search ua:chrome q:callback,q len:empty", ThreatType: "xss"},
	{Pattern: "POST /profile ct:application/json ua:python-requests len:small", ThreatType: "xss"},
	{Pattern: "GET /api/render ua:curl q:template len:empty", ThreatType: "xss"},

	// Path Traversal
	{Pattern: "GET /static ua:curl len:empty", ThreatType: "path_traversal"},
	{Pattern: "GET /download ua:wget q:file len:empty", ThreatType: "path_traversal"},
	{Pattern: "GET /files ua:go-http-client q:name,path len:empty", ThreatType: "path_traversal"},
	{Pattern: "GET /assets ua:python-requests q:resource len:empty", ThreatType: "path_traversal"},
	{Pattern: "GET /api/read ua:curl q:filename len:empty", ThreatType: "path_traversal"},

	// SSRF
	{Pattern: "GET /proxy ua:curl q:url len:empty", ThreatType: "ssrf"},
	{Pattern: "POST /webhook ct:application/json ua:python-requests len:small", ThreatType: "ssrf"},
	{Pattern: "GET /fetch ua:go-http-client q:target len:empty", ThreatType: "ssrf"},
	{Pattern: "POST /import ct:application/json ua:curl len:small", ThreatType: "ssrf"},
	{Pattern: "GET /api/load ua:wget q:source,uri len:empty", ThreatType: "ssrf"},

	// Command Injection
	{Pattern: "POST /exec ct:application/x-www-form-urlencoded ua:curl len:small", ThreatType: "cmdi"},
	{Pattern: "GET /ping ua:curl q:host len:empty", ThreatType: "cmdi"},
	{Pattern: "POST /run ct:application/json ua:python-requests len:small", ThreatType: "cmdi"},
	{Pattern: "GET /api/debug ua:go-http-client q:cmd len:empty", ThreatType: "cmdi"},
	{Pattern: "POST /shell ct:text/plain ua:curl len:small", ThreatType: "cmdi"},

	// Credential Stuffing
	{Pattern: "POST /login ct:application/json ua:python-requests len:small", ThreatType: "cred_stuffing"},
	{Pattern: "POST /auth/token ct:application/x-www-form-urlencoded ua:go-http-client len:small", ThreatType: "cred_stuffing"},
	{Pattern: "POST /api/login ct:application/json ua:curl len:small", ThreatType: "cred_stuffing"},
	{Pattern: "POST /signin ct:application/json ua:httpie len:small", ThreatType: "cred_stuffing"},
	{Pattern: "POST /account/login ct:application/x-www-form-urlencoded ua:python-requests len:medium", ThreatType: "cred_stuffing"},

	// Scanner / Recon
	{Pattern: "GET /admin ua:nikto len:empty", ThreatType: "scanner"},
	{Pattern: "GET /.env ua:gobuster len:empty", ThreatType: "scanner"},
	{Pattern: "GET /wp-admin ua:dirbuster len:empty", ThreatType: "scanner"},
	{Pattern: "GET /phpinfo.php ua:nikto len:empty", ThreatType: "scanner"},
	{Pattern: "GET /api/swagger ua:wfuzz len:empty", ThreatType: "scanner"},
	{Pattern: "GET /.git/config ua:curl len:empty", ThreatType: "scanner"},
	{Pattern: "GET /server-status ua:nmap len:empty", ThreatType: "scanner"},
	{Pattern: "GET /api/v1 ua:masscan len:empty", ThreatType: "scanner"},

	// Bot / Scraper Patterns
	{Pattern: "GET /sitemap.xml ua:python-requests len:empty", ThreatType: "bot"},
	{Pattern: "GET /robots.txt ua:go-http-client len:empty", ThreatType: "bot"},
	{Pattern: "GET /api/products ua:python-requests q:page len:empty", ThreatType: "bot"},
	{Pattern: "GET /listings ua:curl q:category,page len:empty", ThreatType: "bot"},
	{Pattern: "GET /api/prices ua:wget q:id len:empty", ThreatType: "bot"},
	{Pattern: "GET /catalog ua:go-http-client q:limit,offset len:empty", ThreatType: "bot"},
}
