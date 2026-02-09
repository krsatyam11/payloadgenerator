import { Github, Youtube, Linkedin, Instagram } from "lucide-react";

export const siteConfig = {
  author: "Kr Satyam",
  year: 2026,
  role: "3rd Year CSE Student",
  tagline: "Cybersecurity Learner & Offensive Security Enthusiast",
  email: "kaizenbreach@gmail.com",
  socials: {
    github: "https://github.com/krsatyam11",
    linkedin: "https://linkedin.com/in/krsatyam07",
    youtube: "https://youtube.com/@KaizenBreach",
    instagram: "https://instagram.com/kaizenbreach",
    threads: "https://threads.net/@kaizenbreach",
  }
};

export const footerLinks = [
  { name: "GitHub", href: siteConfig.socials.github, icon: Github },
  { name: "LinkedIn", href: siteConfig.socials.linkedin, icon: Linkedin },
  { name: "YouTube", href: siteConfig.socials.youtube, icon: Youtube },
  { name: "Instagram", href: siteConfig.socials.instagram, icon: Instagram },
];