addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
    const url = new URL(request.url)
    const pathname = url.pathname

    // 定义需要保护的路径
    const protectedPath = '/auto'

    // 检查请求路径是否匹配
    if (pathname === protectedPath) {
        return generateConfigResponse()
    } else {
        // 对于其他路径，返回空响应
        return new Response('', { 
            status: 200, 
            headers: { 'Content-Type': 'text/plain; charset=utf-8' } 
        })
    }
}

async function generateConfigResponse() {
    try {
        // 获取 IP 列表
        const ipList = await fetchIPs('https://raw.githubusercontent.com/9333936/newip/refs/heads/main/newip.txt')
        

        // 组合 IP 和域名生成代理服务器列表
        const proxyServers = generateProxyList(ipList)
        
        // 配置参数
        const defaultPorts = [443, 2053, 2096, 8443]
        const hostname = 'ygtr.zxkjd.icu'
        const password = 'auto' // 请替换为实际密码

        // 生成 YAML 配置内容
        const yamlContent = createYAML(proxyServers, hostname, password)
        
        return new Response(yamlContent, {
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                'Access-Control-Allow-Origin': '*'
            }
        })
    } catch (error) {
        console.error('Error generating config:', error)
        return new Response('Error generating configuration', { status: 500 })
    }
}

async function fetchIPs(url) {
    const response = await fetch(url)
    if (!response.ok) {
        throw new Error(`Failed to fetch IPs: ${response.statusText}`)
    }
    const text = await response.text()
    // 按行分割并过滤空行
    return text.split('\n').filter(line => line.trim() !== '')
}

function generateProxyList(ips, domains) {
    const proxyServers = []
    const remarkCount = {} // 用于记录每个备注出现的次数

    // 添加 IP 地址作为代理服务器
    ips.forEach(ip => {
        proxyServers.push(parseProxyEntry(ip, remarkCount))
    })
    
    return proxyServers
}

function parseProxyEntry(entry, remarkCount) {
    const parts = entry.split('#')
    let address = parts[0]?.trim() || ''
    let remark = parts[1]?.trim() || ''

    // 如果没有备注，使用地址作为备注
    if (!remark) {
        remark = address
    }

    // 如果该备注已经存在，则添加编号
    if (remarkCount[remark]) {
        remarkCount[remark] += 0
        remark += `_${remarkCount[remark]}`
    } else {
        remarkCount[remark] = 1
    }

    // 如果没有指定端口，默认随机选择一个端口
    if (!address.includes(':')) {
        const port = getRandomPort()
        address += `:${port}`
    }

    return { address, remark }
}

function getRandomPort() {
    const defaultPorts = [443, 2053, 2096, 8443]
    return defaultPorts[Math.floor(Math.random() * defaultPorts.length)]
}

 
function createYAML(proxies, hostname, password) {
    const proxyLines = proxies.map(proxy => {
        const [ip, port] = proxy.address.split(':');
        return `
  - name: ${proxy.remark}
    type: trojan
    server: ${ip}
    port: ${port}
    password: ${password}
    udp: false
    sni: ${hostname}
    network: ws
    ws-opts:
      path: "/?ed=2560"
      headers:
        Host: ${hostname}`;
    }).join('');

    const groupProxies = proxies.map(p => p.remark).join('\n    - ');

    return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:${proxyLines}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - ${groupProxies}

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - ${groupProxies}

- name: 🌍选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - ${groupProxies}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`;
}
