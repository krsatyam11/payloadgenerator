import { siteConfig, footerLinks } from "../config";

export default function Footer() {
  return (
    <footer className="border-t border-border bg-background/50 backdrop-blur-sm py-8 mt-auto">
      <div className="container mx-auto px-4 flex flex-col md:flex-row justify-between items-center gap-4">
        <div className="text-sm text-muted-foreground font-mono">
          © {siteConfig.year} {siteConfig.author}. All rights reserved.
        </div>
        
        <div className="flex items-center gap-6">
          {footerLinks.map((link) => {
            const Icon = link.icon;
            return (
              <a
                key={link.name}
                href={link.href}
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-primary transition-colors"
                aria-label={link.name}
              >
                <Icon className="h-5 w-5" />
              </a>
            );
          })}
        </div>
      </div>
    </footer>
  );
}