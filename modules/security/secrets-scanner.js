/**
 * Secrets Scanner
 * Scans sysscripts for hardcoded passwords, API keys, tokens before execution
 */

class SecretsScanner {
    constructor() {
        // Regex patterns for common secrets
        this.patterns = {
            aws_access_key: {
                regex: /AKIA[0-9A-Z]{16}/g,
                name: 'AWS Access Key',
                severity: 'critical',
                suggestion: 'Use AWS_ACCESS_KEY_ID environment variable'
            },
            aws_secret_key: {
                regex: /aws_secret_access_key\s*=\s*['"]([A-Za-z0-9/+=]{40})['"]/gi,
                name: 'AWS Secret Key',
                severity: 'critical',
                suggestion: 'Use AWS_SECRET_ACCESS_KEY environment variable'
            },
            github_token: {
                regex: /ghp_[a-zA-Z0-9]{36}/g,
                name: 'GitHub Personal Access Token',
                severity: 'critical',
                suggestion: 'Use GITHUB_TOKEN environment variable'
            },
            generic_api_key: {
                regex: /api[_-]?key\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]/gi,
                name: 'Generic API Key',
                severity: 'high',
                suggestion: 'Use environment variable for API keys'
            },
            password: {
                regex: /password\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
                name: 'Hardcoded Password',
                severity: 'critical',
                suggestion: 'Use environment variable or secrets manager'
            },
            jwt_token: {
                regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
                name: 'JWT Token',
                severity: 'high',
                suggestion: 'Do not hardcode JWT tokens'
            },
            slack_token: {
                regex: /xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]{24,}/g,
                name: 'Slack Token',
                severity: 'critical',
                suggestion: 'Use SLACK_TOKEN environment variable'
            },
            private_key: {
                regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g,
                name: 'Private Key',
                severity: 'critical',
                suggestion: 'Load private keys from secure file storage'
            },
            database_url: {
                regex: /(postgres|mysql|mongodb):\/\/[^:]+:[^@]+@[^\/]+/gi,
                name: 'Database Connection String',
                severity: 'critical',
                suggestion: 'Use DATABASE_URL environment variable'
            },
            ip_address: {
                regex: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
                name: 'IP Address',
                severity: 'low',
                suggestion: 'Consider using hostnames or configuration files'
            }
        };

        this.stats = {
            total_scans: 0,
            secrets_found: 0,
            scripts_blocked: 0
        };
    }

    /**
     * Scan script for secrets
     */
    scan(scriptContent, options = {}) {
        this.stats.total_scans++;

        const findings = [];
        const lines = scriptContent.split('\n');

        // Scan with each pattern
        for (const [patternId, pattern] of Object.entries(this.patterns)) {
            const matches = [...scriptContent.matchAll(pattern.regex)];

            for (const match of matches) {
                // Find line number
                const lineNumber = this.findLineNumber(scriptContent, match.index);
                const lineContent = lines[lineNumber - 1];

                // Extract matched value (mask it for security)
                const secretValue = match[1] || match[0];
                const maskedValue = this.maskSecret(secretValue);

                findings.push({
                    type: patternId,
                    name: pattern.name,
                    severity: pattern.severity,
                    line_number: lineNumber,
                    line_content: lineContent.trim(),
                    matched_value: maskedValue,
                    suggestion: pattern.suggestion,
                    position: {
                        start: match.index,
                        end: match.index + match[0].length
                    }
                });

                this.stats.secrets_found++;
            }
        }

        // Sort by severity
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        const result = {
            has_secrets: findings.length > 0,
            critical_count: findings.filter(f => f.severity === 'critical').length,
            high_count: findings.filter(f => f.severity === 'high').length,
            total_findings: findings.length,
            findings: findings,
            recommendation: this.getRecommendation(findings, options),
            should_block: this.shouldBlock(findings, options)
        };

        if (result.should_block) {
            this.stats.scripts_blocked++;
        }

        return result;
    }

    /**
     * Find line number of match
     */
    findLineNumber(content, index) {
        const upToIndex = content.substring(0, index);
        return upToIndex.split('\n').length;
    }

    /**
     * Mask secret value for display
     */
    maskSecret(secret) {
        if (secret.length <= 8) {
            return '***';
        }
        return secret.substring(0, 4) + '*'.repeat(Math.min(secret.length - 8, 20)) + secret.substring(secret.length - 4);
    }

    /**
     * Get recommendation based on findings
     */
    getRecommendation(findings, options) {
        if (findings.length === 0) {
            return {
                action: 'allow',
                message: '✅ No secrets detected. Safe to execute.'
            };
        }

        const criticalCount = findings.filter(f => f.severity === 'critical').length;
        const highCount = findings.filter(f => f.severity === 'high').length;

        if (criticalCount > 0) {
            return {
                action: 'block',
                message: `🚨 CRITICAL: ${criticalCount} critical secret(s) detected. Execution blocked for security.`,
                details: 'Remove hardcoded secrets before executing this script.'
            };
        }

        if (highCount > 0 && !options.allow_warnings) {
            return {
                action: 'warn',
                message: `⚠️  WARNING: ${highCount} high-severity secret(s) detected. Review before executing.`,
                details: 'Consider using environment variables or a secrets manager.'
            };
        }

        return {
            action: 'warn',
            message: `⚠️  ${findings.length} potential secret(s) detected. Review carefully.`,
            details: 'These may be false positives, but review is recommended.'
        };
    }

    /**
     * Determine if script should be blocked
     */
    shouldBlock(findings, options) {
        if (options.enforce_strict === false) {
            return false;
        }

        const criticalCount = findings.filter(f => f.severity === 'critical').length;
        return criticalCount > 0;
    }

    /**
     * Generate fix suggestions
     */
    generateFix(findings, scriptContent) {
        let fixedScript = scriptContent;
        const environmentVars = new Map();

        for (const finding of findings) {
            // Generate environment variable name
            const envVarName = this.generateEnvVarName(finding.type);

            // Store the secret value
            if (!environmentVars.has(envVarName)) {
                environmentVars.set(envVarName, finding.matched_value);
            }

            // Replace in script
            const lines = fixedScript.split('\n');
            if (finding.line_number <= lines.length) {
                const line = lines[finding.line_number - 1];
                // Replace hardcoded value with environment variable reference
                const newLine = this.replaceWithEnvVar(line, finding, envVarName);
                lines[finding.line_number - 1] = newLine;
                fixedScript = lines.join('\n');
            }
        }

        return {
            fixed_script: fixedScript,
            environment_variables: Object.fromEntries(environmentVars),
            instructions: this.generateInstructions(environmentVars)
        };
    }

    /**
     * Generate environment variable name
     */
    generateEnvVarName(type) {
        const nameMap = {
            aws_access_key: 'AWS_ACCESS_KEY_ID',
            aws_secret_key: 'AWS_SECRET_ACCESS_KEY',
            github_token: 'GITHUB_TOKEN',
            generic_api_key: 'API_KEY',
            password: 'PASSWORD',
            jwt_token: 'JWT_TOKEN',
            slack_token: 'SLACK_TOKEN',
            database_url: 'DATABASE_URL'
        };

        return nameMap[type] || type.toUpperCase();
    }

    /**
     * Replace hardcoded value with environment variable
     */
    replaceWithEnvVar(line, finding, envVarName) {
        // This is simplified - would need more sophisticated parsing
        return line.replace(finding.matched_value, `os.environ.get('${envVarName}')`);
    }

    /**
     * Generate instructions for using environment variables
     */
    generateInstructions(environmentVars) {
        return `
To use this script securely:

1. Set the following environment variables:

${Array.from(environmentVars.entries()).map(([key, value]) =>
    `   export ${key}="${value}"`
).join('\n')}

2. Run the script with these variables available in the environment.

3. Consider using a secrets manager like:
   - HashiCorp Vault
   - AWS Secrets Manager
   - Azure Key Vault
   - Environment-specific .env files (with .gitignore)

4. Never commit secrets to version control!
        `.trim();
    }

    /**
     * Scan and auto-fix script
     */
    scanAndFix(scriptContent, options = {}) {
        const scanResult = this.scan(scriptContent, options);

        if (!scanResult.has_secrets) {
            return {
                ...scanResult,
                fix: null
            };
        }

        const fix = this.generateFix(scanResult.findings, scriptContent);

        return {
            ...scanResult,
            fix: fix
        };
    }

    /**
     * Get scanner statistics
     */
    getStats() {
        return {
            ...this.stats,
            block_rate: this.stats.total_scans > 0
                ? (this.stats.scripts_blocked / this.stats.total_scans * 100).toFixed(2) + '%'
                : '0%'
        };
    }
}

module.exports = SecretsScanner;
