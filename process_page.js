#!/usr/bin/env node

/**
 * Agentic Browser Security Pipeline - Step 1: HTML to Markdown Processor
 * Converts HTML content to markdown while preserving structure for agent processing
 * 
 * Usage: node process_page.js <url> or echo "html" | node process_page.js
 */

const fs = require('fs');
const https = require('https');
const http = require('http');
const { JSDOM } = require('jsdom');
const TurndownService = require('turndown');

class PageProcessor {
    constructor() {
        this.turndownService = new TurndownService({
            headingStyle: 'atx',
            bulletListMarker: '-',
            codeBlockStyle: 'fenced',
            fence: '```',
            emDelimiter: '_',
            strongDelimiter: '**',
            linkStyle: 'inlined',
            linkReferenceStyle: 'full'
        });

        // Remove potentially dangerous elements before conversion
        this.turndownService.remove(['script', 'style', 'iframe', 'object', 'embed', 'form', 'input']);
        
        // Custom rules for better security
        this.turndownService.addRule('removeComments', {
            filter: function(node) {
                return node.nodeType === 8; // Comment nodes
            },
            replacement: function() {
                return '';
            }
        });

        this.turndownService.addRule('sanitizeLinks', {
            filter: 'a',
            replacement: function(content, node) {
                const href = node.getAttribute('href');
                if (!href || href.startsWith('javascript:') || href.startsWith('data:')) {
                    return content;
                }
                return '[' + content + '](' + href + ')';
            }
        });
    }

    async fetchPage(url) {
        return new Promise((resolve, reject) => {
            const client = url.startsWith('https:') ? https : http;
            
            const options = {
                headers: {
                    'User-Agent': 'AgenticBrowser/1.0 Security Scanner',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                },
                timeout: 10000
            };

            client.get(url, options, (res) => {
                if (res.statusCode !== 200) {
                    reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
                    return;
                }

                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve(data));
            }).on('error', reject).on('timeout', () => {
                reject(new Error('Request timeout'));
            });
        });
    }

    processHTML(html) {
        try {
            // Parse with JSDOM for safer handling
            const dom = new JSDOM(html, {
                features: {
                    FetchExternalResources: false,
                    ProcessExternalResources: false,
                    SkipExternalResources: true
                }
            });

            const document = dom.window.document;
            
            // Remove dangerous attributes
            const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur'];
            document.querySelectorAll('*').forEach(element => {
                dangerousAttrs.forEach(attr => {
                    if (element.hasAttribute(attr)) {
                        element.removeAttribute(attr);
                    }
                });
            });

            // Convert to markdown
            const markdown = this.turndownService.turndown(document.body || document.documentElement);
            
            // Add metadata
            const title = document.querySelector('title')?.textContent || 'Untitled';
            const description = document.querySelector('meta[name="description"]')?.getAttribute('content') || '';
            
            const output = {
                title: title.trim(),
                description: description.trim(),
                content: markdown,
                processed_at: new Date().toISOString(),
                word_count: markdown.split(/\s+/).length
            };

            return JSON.stringify(output, null, 2);

        } catch (error) {
            throw new Error(`HTML processing failed: ${error.message}`);
        }
    }

    async run() {
        try {
            let html = '';

            if (process.argv[2]) {
                // URL provided as argument
                const url = process.argv[2];
                if (!url.match(/^https?:\/\//)) {
                    throw new Error('Invalid URL format. Must start with http:// or https://');
                }
                html = await this.fetchPage(url);
            } else {
                // Read from stdin
                if (process.stdin.isTTY) {
                    console.error('Usage: node process_page.js <url> or echo "html" | node process_page.js');
                    process.exit(1);
                }

                const chunks = [];
                for await (const chunk of process.stdin) {
                    chunks.push(chunk);
                }
                html = Buffer.concat(chunks).toString();
            }

            const result = this.processHTML(html);
            console.log(result);

        } catch (error) {
            console.error('Error:', error.message);
            process.exit(1);
        }
    }
}

// Run if called directly
if (require.main === module) {
    const processor = new PageProcessor();
    processor.run();
}

module.exports = PageProcessor;
