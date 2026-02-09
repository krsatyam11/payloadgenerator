import { siteConfig, footerLinks } from "../config";

export default function Footer() {
  return (
    <footer className="border-t border-white/5 bg-black/50 backdrop-blur-sm py-6 mt-auto">
      <div className="container mx-auto px-4 flex flex-col md:flex-row justify-between items-center gap-4">
        <div className="text-xs text-muted-foreground font-mono">
          <span className="text-cyan-500">root@payload-ui</span>:~$ ./copyright --year {siteConfig.year} --author "{siteConfig.author}"
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
                className="text-muted-foreground hover:text-cyan-400 transition-colors transform hover:scale-110"
                aria-label={link.name}
              >
                <Icon className="h-4 w-4" />
              </a>
            );
          })}
        </div>
      </div>
    </footer>
  );
}