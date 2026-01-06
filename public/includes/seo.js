/**
 * SEO Include Script - After Dark Systems
 *
 * Include this script in your HTML <head> section:
 * <script src="https://www.afterdarksys.com/includes/seo.js"></script>
 *
 * Or with custom configuration:
 * <script>
 *   window.ADS_SEO_CONFIG = {
 *     title: "My Page Title",
 *     description: "My page description",
 *     keywords: "keyword1, keyword2",
 *     url: "https://example.com/page",
 *     image: "https://example.com/image.png",
 *     type: "article"
 *   };
 * </script>
 * <script src="https://www.afterdarksys.com/includes/seo.js"></script>
 */

(function() {
    'use strict';

    // Configuration - Replace these IDs with your actual IDs
    const CONFIG = {
        GTM_ID: 'GTM-XXXXXXX',        // Google Tag Manager
        GA4_ID: 'G-XXXXXXXXXX',        // Google Analytics 4
        FB_PIXEL_ID: 'XXXXXXXXXXXXXXXXX', // Facebook Pixel
        CLARITY_ID: 'XXXXXXXXXX'       // Microsoft Clarity
    };

    // Default SEO values
    const defaults = {
        siteName: 'After Dark Systems',
        title: 'After Dark Systems - Enterprise Security, Cloud & DevOps Consulting',
        description: 'GSA-cleared certified engineers delivering mission-critical Security, Software, Cloud, and DevOps solutions to Fortune 500 companies, Government Contractors, Tier 1 ISPs, and Financial Services institutions.',
        keywords: 'enterprise security, cloud consulting, DevOps, cybersecurity, GSA cleared, FedRAMP, CMMC, government contractors, Fortune 500, IT consulting, AWS, Oracle Cloud, Cloudflare',
        url: window.location.href,
        image: 'https://www.afterdarksys.com/assets/og-image.png',
        type: 'website',
        twitterHandle: '@afterdarksys',
        themeColor: '#283593'
    };

    // Merge user config with defaults
    const config = Object.assign({}, defaults, window.ADS_SEO_CONFIG || {});

    // Helper function to create and append meta tags
    function addMeta(name, content, isProperty = false) {
        if (!content) return;
        const meta = document.createElement('meta');
        meta.setAttribute(isProperty ? 'property' : 'name', name);
        meta.setAttribute('content', content);
        document.head.appendChild(meta);
    }

    // Helper function to add link tags
    function addLink(rel, href, attrs = {}) {
        const link = document.createElement('link');
        link.rel = rel;
        link.href = href;
        Object.keys(attrs).forEach(key => link.setAttribute(key, attrs[key]));
        document.head.appendChild(link);
    }

    // Helper function to add script tags
    function addScript(src, async = true) {
        const script = document.createElement('script');
        script.src = src;
        script.async = async;
        document.head.appendChild(script);
    }

    // Helper function to add inline script
    function addInlineScript(code) {
        const script = document.createElement('script');
        script.textContent = code;
        document.head.appendChild(script);
    }

    // Helper function to add JSON-LD structured data
    function addJsonLd(data) {
        const script = document.createElement('script');
        script.type = 'application/ld+json';
        script.textContent = JSON.stringify(data);
        document.head.appendChild(script);
    }

    // ============================================
    // PRIMARY SEO META TAGS
    // ============================================
    addMeta('title', config.title);
    addMeta('description', config.description);
    addMeta('keywords', config.keywords);
    addMeta('author', 'After Dark Systems, LLC');
    addMeta('robots', 'index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1');
    addMeta('googlebot', 'index, follow');
    addMeta('bingbot', 'index, follow');
    addLink('canonical', config.url);

    // ============================================
    // OPEN GRAPH / FACEBOOK META TAGS
    // ============================================
    addMeta('og:type', config.type, true);
    addMeta('og:url', config.url, true);
    addMeta('og:title', config.title, true);
    addMeta('og:description', config.description, true);
    addMeta('og:image', config.image, true);
    addMeta('og:image:width', '1200', true);
    addMeta('og:image:height', '630', true);
    addMeta('og:site_name', config.siteName, true);
    addMeta('og:locale', 'en_US', true);

    // ============================================
    // TWITTER CARD META TAGS
    // ============================================
    addMeta('twitter:card', 'summary_large_image');
    addMeta('twitter:site', config.twitterHandle);
    addMeta('twitter:creator', config.twitterHandle);
    addMeta('twitter:url', config.url);
    addMeta('twitter:title', config.title);
    addMeta('twitter:description', config.description);
    addMeta('twitter:image', config.image);

    // ============================================
    // ADDITIONAL SEO TAGS
    // ============================================
    addMeta('theme-color', config.themeColor);
    addMeta('msapplication-TileColor', config.themeColor);
    addMeta('apple-mobile-web-app-capable', 'yes');
    addMeta('apple-mobile-web-app-status-bar-style', 'black-translucent');
    addMeta('format-detection', 'telephone=no');

    // DNS Prefetch for performance
    addLink('dns-prefetch', '//www.google-analytics.com');
    addLink('dns-prefetch', '//www.googletagmanager.com');
    addLink('dns-prefetch', '//fonts.googleapis.com');
    addLink('dns-prefetch', '//fonts.gstatic.com');

    // Preconnect for faster loading
    addLink('preconnect', 'https://fonts.googleapis.com', { crossorigin: '' });
    addLink('preconnect', 'https://fonts.gstatic.com', { crossorigin: '' });

    // ============================================
    // STRUCTURED DATA (JSON-LD) - Organization
    // ============================================
    addJsonLd({
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "After Dark Systems, LLC",
        "alternateName": "After Dark Systems",
        "url": "https://www.afterdarksys.com",
        "logo": "https://www.afterdarksys.com/assets/logo.png",
        "description": config.description,
        "foundingDate": "2020",
        "address": {
            "@type": "PostalAddress",
            "addressCountry": "US"
        },
        "contactPoint": {
            "@type": "ContactPoint",
            "contactType": "customer service",
            "url": "https://support.afterdarksys.com",
            "availableLanguage": ["English"]
        },
        "sameAs": [
            "https://twitter.com/afterdarksys",
            "https://linkedin.com/company/after-dark-systems",
            "https://github.com/afterdarksys"
        ],
        "knowsAbout": [
            "Enterprise Security",
            "Cloud Computing",
            "DevOps",
            "Cybersecurity",
            "FedRAMP Compliance",
            "CMMC Compliance",
            "AWS",
            "Oracle Cloud",
            "Cloudflare",
            "DNS Security",
            "DNSSEC",
            "Network Infrastructure"
        ]
    });

    // ============================================
    // STRUCTURED DATA (JSON-LD) - WebSite with SearchAction
    // ============================================
    addJsonLd({
        "@context": "https://schema.org",
        "@type": "WebSite",
        "name": "After Dark Systems",
        "url": "https://www.afterdarksys.com",
        "potentialAction": {
            "@type": "SearchAction",
            "target": {
                "@type": "EntryPoint",
                "urlTemplate": "https://www.afterdarksys.com/search-results.php?q={search_term_string}"
            },
            "query-input": "required name=search_term_string"
        }
    });

    // ============================================
    // GOOGLE TAG MANAGER
    // ============================================
    if (CONFIG.GTM_ID !== 'GTM-XXXXXXX') {
        window.dataLayer = window.dataLayer || [];
        window.dataLayer.push({
            'gtm.start': new Date().getTime(),
            event: 'gtm.js'
        });
        addScript('https://www.googletagmanager.com/gtm.js?id=' + CONFIG.GTM_ID);
    }

    // ============================================
    // GOOGLE ANALYTICS 4
    // ============================================
    if (CONFIG.GA4_ID !== 'G-XXXXXXXXXX') {
        addScript('https://www.googletagmanager.com/gtag/js?id=' + CONFIG.GA4_ID);
        addInlineScript(`
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
            gtag('config', '${CONFIG.GA4_ID}', {
                'anonymize_ip': true,
                'cookie_flags': 'SameSite=None;Secure'
            });
        `);
    }

    // ============================================
    // FACEBOOK/META PIXEL
    // ============================================
    if (CONFIG.FB_PIXEL_ID !== 'XXXXXXXXXXXXXXXXX') {
        addInlineScript(`
            !function(f,b,e,v,n,t,s)
            {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
            n.callMethod.apply(n,arguments):n.queue.push(arguments)};
            if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
            n.queue=[];t=b.createElement(e);t.async=!0;
            t.src=v;s=b.getElementsByTagName(e)[0];
            s.parentNode.insertBefore(t,s)}(window, document,'script',
            'https://connect.facebook.net/en_US/fbevents.js');
            fbq('init', '${CONFIG.FB_PIXEL_ID}');
            fbq('track', 'PageView');
        `);
    }

    // ============================================
    // MICROSOFT CLARITY
    // ============================================
    if (CONFIG.CLARITY_ID !== 'XXXXXXXXXX') {
        addInlineScript(`
            (function(c,l,a,r,i,t,y){
                c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
                t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
                y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
            })(window, document, "clarity", "script", "${CONFIG.CLARITY_ID}");
        `);
    }

    // Log initialization
    console.log('[ADS SEO] After Dark Systems SEO initialized');

})();
