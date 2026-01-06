/**
 * Corporate Backlinks / Infrastructure Directory - After Dark Systems
 *
 * Include this script at the bottom of your HTML page (before </body>):
 * <script src="https://www.afterdarksys.com/includes/backlinks.js"></script>
 *
 * Or with custom configuration:
 * <script>
 *   window.ADS_BACKLINKS_CONFIG = {
 *     showVisualFooter: true,  // Set to false for structured data only
 *     targetElement: 'footer', // CSS selector or element ID to insert before
 *     theme: 'dark'            // 'dark' or 'light'
 *   };
 * </script>
 * <script src="https://www.afterdarksys.com/includes/backlinks.js"></script>
 */

(function() {
    'use strict';

    // Configuration
    const config = Object.assign({
        showVisualFooter: true,
        targetElement: null,
        theme: 'dark',
        gtmId: 'GTM-XXXXXXX'
    }, window.ADS_BACKLINKS_CONFIG || {});

    // Ecosystem platforms data
    const ecosystemPlatforms = {
        dating: {
            name: 'Dating & Social',
            platforms: [
                { name: 'NerdyCupid.com', url: 'https://nerdycupid.com', desc: 'Geek dating platform' },
                { name: 'NerdyCupid.ai', url: 'https://nerdycupid.ai', desc: 'AI-powered dating' },
                { name: 'Undateable.me', url: 'https://undateable.me', desc: 'Second chances dating' },
                { name: 'Lonely.FYI', url: 'https://lonely.fyi', desc: 'Anonymous chat & video' },
                { name: '9Lives.xyz', url: 'https://9lives.xyz', desc: 'Cat lovers community' }
            ]
        },
        jobs: {
            name: 'Jobs & Career',
            platforms: [
                { name: 'OutOfWork.Life', url: 'https://outofwork.life', desc: 'Gig economy job board' }
            ]
        },
        science: {
            name: 'Science & Security',
            platforms: [
                { name: 'DNSScience.io', url: 'https://dnsscience.io', desc: 'DNS & email security research' },
                { name: 'HostScience.io', url: 'https://hostscience.io', desc: 'ARM64 cloud hosting' },
                { name: 'IPScience.io', url: 'https://ipscience.io', desc: 'IP intelligence & geolocation' },
                { name: 'InternetData.io', url: 'https://internetdata.io', desc: 'Internet infrastructure data' }
            ]
        },
        domains: {
            name: 'Domains & Web3',
            platforms: [
                { name: 'Web3DNS.io', url: 'https://web3dns.io', desc: 'Web3 domain management' },
                { name: 'FlipDomain.io', url: 'https://flipdomain.io', desc: 'Domain marketplace' }
            ]
        },
        health: {
            name: 'Health & Wellness',
            platforms: [
                { name: 'DiseaseZone', url: 'https://disease.zone', desc: 'Real-time disease tracking' },
                { name: 'SmokeOut.NYC', url: 'https://smokeout.nyc', desc: 'NYC air quality monitoring' }
            ]
        },
        media: {
            name: 'Media & Content',
            platforms: [
                { name: 'Politics.Place', url: 'https://politics.place', desc: 'Political discussion platform' },
                { name: 'HeartOfAToaster.com', url: 'https://heartofatoaster.com', desc: 'Portfolio & blog platform' },
                { name: 'SexyCa.ms', url: 'https://sexyca.ms', desc: 'Premium streaming platform' }
            ]
        },
        infrastructure: {
            name: 'Corporate Infrastructure',
            platforms: [
                { name: 'AfterDarkSys.com', url: 'https://www.afterdarksys.com', desc: 'Corporate headquarters' },
                { name: 'Login Portal', url: 'https://login.afterdarksys.com', desc: 'Single sign-on' },
                { name: 'Support Center', url: 'https://support.afterdarksys.com', desc: 'Technical support' },
                { name: 'Status Page', url: 'https://status.afterdarksys.com', desc: 'System status' },
                { name: 'API Gateway', url: 'https://api.afterdarksys.com', desc: 'Developer API' },
                { name: 'Catalog', url: 'https://catalog.afterdarksys.com', desc: 'Platform catalog' }
            ]
        },
        coming_soon: {
            name: 'Coming Soon',
            platforms: [
                { name: 'GetThis.Money', url: 'https://getthis.money', desc: 'Financial management' },
                { name: 'GetThis.World', url: 'https://getthis.world', desc: 'Global marketplace' }
            ]
        }
    };

    // Helper function to add JSON-LD structured data
    function addJsonLd(data) {
        const script = document.createElement('script');
        script.type = 'application/ld+json';
        script.textContent = JSON.stringify(data);
        document.head.appendChild(script);
    }

    // Get all platforms as flat array
    function getAllPlatforms() {
        const all = [];
        Object.values(ecosystemPlatforms).forEach(category => {
            category.platforms.forEach(platform => all.push(platform));
        });
        return all;
    }

    // ============================================
    // STRUCTURED DATA (JSON-LD) - Ecosystem ItemList
    // ============================================
    const allPlatforms = getAllPlatforms();
    addJsonLd({
        "@context": "https://schema.org",
        "@type": "ItemList",
        "name": "After Dark Systems Ecosystem",
        "description": "The complete After Dark Systems platform ecosystem",
        "numberOfItems": allPlatforms.length,
        "itemListElement": allPlatforms.map((platform, index) => ({
            "@type": "ListItem",
            "position": index + 1,
            "item": {
                "@type": "WebSite",
                "name": platform.name,
                "url": platform.url,
                "description": platform.desc
            }
        }))
    });

    // ============================================
    // STRUCTURED DATA (JSON-LD) - Corporate Relations
    // ============================================
    addJsonLd({
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "After Dark Systems, LLC",
        "url": "https://www.afterdarksys.com",
        "subOrganization": [
            {
                "@type": "Organization",
                "name": "DNSScience",
                "url": "https://dnsscience.io",
                "description": "DNS & Email Security Research Platform"
            },
            {
                "@type": "Organization",
                "name": "HostScience",
                "url": "https://hostscience.io",
                "description": "ARM64 Cloud Hosting Solutions"
            },
            {
                "@type": "Organization",
                "name": "IPScience",
                "url": "https://ipscience.io",
                "description": "IP Intelligence & Network Analysis"
            },
            {
                "@type": "Organization",
                "name": "NerdyCupid",
                "url": "https://nerdycupid.com",
                "description": "Geek & Nerd Dating Platform"
            }
        ]
    });

    // ============================================
    // VISUAL FOOTER
    // ============================================
    if (config.showVisualFooter) {
        const isDark = config.theme === 'dark';
        const currentYear = new Date().getFullYear();

        const styles = `
            .ads-ecosystem-footer {
                background: ${isDark ? 'linear-gradient(180deg, #0a0a1a 0%, #0d1b2a 100%)' : 'linear-gradient(180deg, #f8f9fa 0%, #ffffff 100%)'};
                border-top: 1px solid ${isDark ? 'rgba(0, 245, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'};
                padding: 3rem 1rem 1.5rem;
                margin-top: 4rem;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                color: ${isDark ? '#ffffff' : '#333333'};
            }
            .ads-ecosystem-footer-container {
                max-width: 1400px;
                margin: 0 auto;
            }
            .ads-ecosystem-footer h4 {
                color: ${isDark ? '#00f5ff' : '#283593'};
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 0.75rem;
                font-weight: 600;
            }
            .ads-ecosystem-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 2rem;
                margin-bottom: 2rem;
            }
            .ads-ecosystem-column ul {
                list-style: none;
                padding: 0;
                margin: 0;
            }
            .ads-ecosystem-column li {
                margin-bottom: 0.4rem;
            }
            .ads-ecosystem-column a {
                color: ${isDark ? '#a0aec0' : '#666666'};
                text-decoration: none;
                font-size: 0.85rem;
                transition: color 0.2s ease;
            }
            .ads-ecosystem-column a:hover {
                color: ${isDark ? '#ffffff' : '#283593'};
            }
            .ads-ecosystem-footer-bottom {
                border-top: 1px solid ${isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'};
                padding-top: 1.5rem;
                display: flex;
                flex-wrap: wrap;
                justify-content: space-between;
                align-items: center;
                gap: 1rem;
            }
            .ads-ecosystem-footer-brand {
                color: ${isDark ? '#ffffff' : '#333333'};
                font-weight: 600;
                font-size: 1rem;
            }
            .ads-ecosystem-footer-brand span {
                color: ${isDark ? '#00f5ff' : '#283593'};
            }
            .ads-ecosystem-footer-legal {
                color: ${isDark ? '#64748b' : '#888888'};
                font-size: 0.75rem;
            }
            .ads-ecosystem-footer-legal a {
                color: ${isDark ? '#64748b' : '#888888'};
                text-decoration: none;
                margin-left: 1rem;
            }
            .ads-ecosystem-footer-legal a:hover {
                color: ${isDark ? '#ffffff' : '#283593'};
            }
            .ads-ecosystem-stats {
                display: flex;
                gap: 2rem;
                color: ${isDark ? '#64748b' : '#888888'};
                font-size: 0.75rem;
                margin-bottom: 1.5rem;
                padding-bottom: 1.5rem;
                border-bottom: 1px solid ${isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)'};
            }
            .ads-ecosystem-stat {
                text-align: center;
            }
            .ads-ecosystem-stat-value {
                color: ${isDark ? '#00f5ff' : '#283593'};
                font-size: 1.25rem;
                font-weight: 700;
                display: block;
            }
            @media (max-width: 768px) {
                .ads-ecosystem-grid {
                    grid-template-columns: repeat(2, 1fr);
                }
                .ads-ecosystem-stats {
                    justify-content: center;
                    flex-wrap: wrap;
                }
            }
        `;

        // Build footer HTML
        let columnsHtml = '';
        Object.entries(ecosystemPlatforms).forEach(([key, category]) => {
            let linksHtml = '';
            category.platforms.forEach(platform => {
                const target = key === 'coming_soon' ? '' : ' target="_blank" rel="noopener"';
                linksHtml += `<li><a href="${platform.url}" title="${platform.desc}"${target}>${platform.name}</a></li>`;
            });
            columnsHtml += `
                <div class="ads-ecosystem-column">
                    <h4>${category.name}</h4>
                    <ul>${linksHtml}</ul>
                </div>
            `;
        });

        const footerHtml = `
            <footer class="ads-ecosystem-footer" role="contentinfo">
                <style>${styles}</style>
                <div class="ads-ecosystem-footer-container">
                    <nav class="ads-ecosystem-stats" aria-label="Ecosystem statistics">
                        <div class="ads-ecosystem-stat">
                            <span class="ads-ecosystem-stat-value">20+</span>
                            Live Platforms
                        </div>
                        <div class="ads-ecosystem-stat">
                            <span class="ads-ecosystem-stat-value">$150M+</span>
                            Valuation
                        </div>
                        <div class="ads-ecosystem-stat">
                            <span class="ads-ecosystem-stat-value">$8M+</span>
                            API Revenue Potential
                        </div>
                        <div class="ads-ecosystem-stat">
                            <span class="ads-ecosystem-stat-value">24/7</span>
                            Global Operations
                        </div>
                    </nav>
                    <nav class="ads-ecosystem-grid" aria-label="After Dark Systems platforms">
                        ${columnsHtml}
                    </nav>
                    <div class="ads-ecosystem-footer-bottom">
                        <div class="ads-ecosystem-footer-brand">
                            <span>After Dark</span> Systems, LLC
                        </div>
                        <div class="ads-ecosystem-footer-legal">
                            &copy; ${currentYear} After Dark Systems, LLC. All rights reserved.
                            <a href="https://www.afterdarksys.com/privacy">Privacy</a>
                            <a href="https://www.afterdarksys.com/terms">Terms</a>
                            <a href="https://www.afterdarksys.com/contact.php">Contact</a>
                        </div>
                    </div>
                </div>
            </footer>
        `;

        // Insert footer into the page
        const container = document.createElement('div');
        container.innerHTML = footerHtml;
        const footer = container.firstElementChild;

        if (config.targetElement) {
            const target = document.querySelector(config.targetElement);
            if (target) {
                target.parentNode.insertBefore(footer, target);
            } else {
                document.body.appendChild(footer);
            }
        } else {
            document.body.appendChild(footer);
        }
    }

    // ============================================
    // GOOGLE TAG MANAGER (NOSCRIPT)
    // ============================================
    if (config.gtmId !== 'GTM-XXXXXXX') {
        const noscript = document.createElement('noscript');
        noscript.innerHTML = `<iframe src="https://www.googletagmanager.com/ns.html?id=${config.gtmId}" height="0" width="0" style="display:none;visibility:hidden"></iframe>`;
        document.body.insertBefore(noscript, document.body.firstChild);
    }

    // Log initialization
    console.log('[ADS Backlinks] After Dark Systems ecosystem footer initialized');

    // Expose platforms data for external use
    window.ADS_ECOSYSTEM = ecosystemPlatforms;

})();
