/**
 * Code snippet generator for API Playground
 * Generates code examples in Python, Go, Node.js, PHP, and cURL
 */

class CodeSnippetGenerator {
  constructor(baseURL, apiSite) {
    this.baseURL = baseURL.replace(/\/$/, '');
    this.apiSite = apiSite;
  }

  generateAll(endpoint, method = 'GET', headers = {}, queryParams = {}, body = null, apiKey = null) {
    return {
      python: this.generatePython(endpoint, method, headers, queryParams, body, apiKey),
      go: this.generateGo(endpoint, method, headers, queryParams, body, apiKey),
      node: this.generateNode(endpoint, method, headers, queryParams, body, apiKey),
      php: this.generatePHP(endpoint, method, headers, queryParams, body, apiKey),
      curl: this.generateCURL(endpoint, method, headers, queryParams, body, apiKey)
    };
  }

  buildURL(endpoint, queryParams) {
    let url = this.baseURL + endpoint;
    if (queryParams && Object.keys(queryParams).length > 0) {
      const params = new URLSearchParams(queryParams);
      url += '?' + params.toString();
    }
    return url;
  }

  mergeHeaders(headers, apiKey) {
    const merged = { ...headers };
    if (apiKey) {
      merged['X-API-Key'] = apiKey;
    }
    if (!merged['Content-Type']) {
      merged['Content-Type'] = 'application/json';
    }
    return merged;
  }

  generatePython(endpoint, method, headers, queryParams, body, apiKey) {
    const url = this.buildURL(endpoint, queryParams);
    const mergedHeaders = this.mergeHeaders(headers, apiKey);

    let code = `import requests\n\nurl = "${url}"\n`;

    if (Object.keys(mergedHeaders).length > 0) {
      code += `\nheaders = ${JSON.stringify(mergedHeaders, null, 4)}\n`;
    }

    if (body) {
      code += `\npayload = ${JSON.stringify(body, null, 4)}\n`;
    }

    code += `\nresponse = requests.${method.toLowerCase()}(url`;
    if (Object.keys(mergedHeaders).length > 0) {
      code += ', headers=headers';
    }
    if (body) {
      code += ', json=payload';
    }
    code += `)\n\nprint(f"Status Code: {response.status_code}")\nprint(f"Response: {response.json()}")\n`;

    return code;
  }

  generateGo(endpoint, method, headers, queryParams, body, apiKey) {
    const url = this.buildURL(endpoint, queryParams);
    const mergedHeaders = this.mergeHeaders(headers, apiKey);

    let code = `package main\n\nimport (\n    "bytes"\n    "encoding/json"\n    "fmt"\n    "io"\n    "net/http"\n)\n\nfunc main() {\n`;
    code += `    url := "${url}"\n\n`;

    if (body) {
      code += `    payload := []byte(\`${JSON.stringify(body)}\`)\n`;
      code += `    req, err := http.NewRequest("${method}", url, bytes.NewBuffer(payload))\n`;
    } else {
      code += `    req, err := http.NewRequest("${method}", url, nil)\n`;
    }

    code += `    if err != nil {\n        panic(err)\n    }\n\n`;

    if (Object.keys(mergedHeaders).length > 0) {
      for (const [key, value] of Object.entries(mergedHeaders)) {
        code += `    req.Header.Set("${key}", "${value}")\n`;
      }
      code += '\n';
    }

    code += `    client := &http.Client{}\n`;
    code += `    resp, err := client.Do(req)\n`;
    code += `    if err != nil {\n        panic(err)\n    }\n`;
    code += `    defer resp.Body.Close()\n\n`;
    code += `    body, _ := io.ReadAll(resp.Body)\n`;
    code += `    fmt.Printf("Status Code: %d\\n", resp.StatusCode)\n`;
    code += `    fmt.Printf("Response: %s\\n", string(body))\n}\n`;

    return code;
  }

  generateNode(endpoint, method, headers, queryParams, body, apiKey) {
    const url = this.buildURL(endpoint, queryParams);
    const mergedHeaders = this.mergeHeaders(headers, apiKey);

    let code = `const axios = require('axios');\n\nconst url = '${url}';\n`;

    if (Object.keys(mergedHeaders).length > 0) {
      code += `\nconst headers = ${JSON.stringify(mergedHeaders, null, 2)};\n`;
    }

    if (body) {
      code += `\nconst body = ${JSON.stringify(body, null, 2)};\n`;
    }

    code += `\naxios({\n  method: '${method.toLowerCase()}',\n  url: url`;

    if (Object.keys(mergedHeaders).length > 0) {
      code += ',\n  headers: headers';
    }
    if (body) {
      code += ',\n  data: body';
    }

    code += `\n})\n  .then(response => {\n    console.log('Status Code:', response.status);\n    console.log('Response:', response.data);\n  })\n  .catch(error => {\n    console.error('Error:', error.message);\n  });\n`;

    return code;
  }

  generatePHP(endpoint, method, headers, queryParams, body, apiKey) {
    const url = this.buildURL(endpoint, queryParams);
    const mergedHeaders = this.mergeHeaders(headers, apiKey);

    let code = `<?php\n\n$url = "${url}";\n$ch = curl_init($url);\n\n`;
    code += `curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);\n`;
    code += `curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "${method}");\n\n`;

    if (Object.keys(mergedHeaders).length > 0) {
      code += `$headers = [\n`;
      for (const [key, value] of Object.entries(mergedHeaders)) {
        code += `    "${key}: ${value}",\n`;
      }
      code += `];\ncurl_setopt($ch, CURLOPT_HTTPHEADER, $headers);\n\n`;
    }

    if (body) {
      code += `$payload = '${JSON.stringify(body)}';\n`;
      code += `curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);\n\n`;
    }

    code += `$response = curl_exec($ch);\n`;
    code += `$statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);\n\n`;
    code += `if (curl_errno($ch)) {\n`;
    code += `    echo 'Error: ' . curl_error($ch);\n`;
    code += `} else {\n`;
    code += `    echo "Status Code: " . $statusCode . "\\n";\n`;
    code += `    echo "Response: " . $response . "\\n";\n`;
    code += `}\n\ncurl_close($ch);\n?>\n`;

    return code;
  }

  generateCURL(endpoint, method, headers, queryParams, body, apiKey) {
    const url = this.buildURL(endpoint, queryParams);
    const mergedHeaders = this.mergeHeaders(headers, apiKey);

    let code = `curl -X ${method} "${url}"`;

    if (Object.keys(mergedHeaders).length > 0) {
      for (const [key, value] of Object.entries(mergedHeaders)) {
        code += ` \\\n  -H "${key}: ${value}"`;
      }
    }

    if (body) {
      code += ` \\\n  -d '${JSON.stringify(body)}'`;
    }

    return code;
  }
}

module.exports = CodeSnippetGenerator;
