addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
    const url = new URL(request.url)
    const pathname = url.pathname

    // 定义需要保护的路径
    const protectedPath = '/yg-tor'

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
        
        // 获取域名列表
        const domainList = await fetchDomains('https://raw.githubusercontent.com/9333936/newip/refs/heads/main/yxym.txt')
        
        // 组合 IP 和域名生成代理服务器列表
        const proxyServers = generateProxyList(ipList, domainList)
        
        // 配置参数
        const defaultPorts = [443, 2053, 2096, 8443]
        const hostname = 'yg-tor.zxkjd.icu'
        const password = 'yg-tor' // 请替换为实际密码

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

async function fetchDomains(url) {
    const response = await fetch(url)
    if (!response.ok) {
        throw new Error(`Failed to fetch domains: ${response.statusText}`)
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
    
    // 添加域名作为代理服务器
    domains.forEach(domain => {
        proxyServers.push(parseProxyEntry(domain, remarkCount))
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
        remarkCount[remark] += 1
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
    const lines = []

    // 添加全局配置
    lines.push(`port: 443`)
    lines.push('allow-lan: true')
    lines.push('mode: rule')
    lines.push('log-level: info')
    lines.push('unified-delay: true')
    lines.push('global-client-fingerprint: chrome')

    // 添加 DNS 配置
    lines.push('dns:')
    lines.push('  enable: true')
    lines.push('  listen: :53')
    lines.push('  ipv6: true')
    lines.push('  enhanced-mode: fake-ip')
    lines.push('  fake-ip-range: 198.18.0.1/16')
    lines.push('  default-nameservers:')
    lines.push('    - 223.5.5.5')
    lines.push('    - 114.114.114.114')
    lines.push('    - 8.8.8.8')
    lines.push('  nameserver:')
    lines.push('    - https://dns.alidns.com/dns-query')
    lines.push('    - https://doh.pub/dns-query')
    lines.push('  fallback:')
    lines.push('    - https://1.0.0.1/dns-query')
    lines.push('    - tls://dns.google')
    lines.push('  fallback-filter:')
    lines.push('    geoip: true')
    lines.push('    geoip-code: CN')
    lines.push('    ipcidr:')
    lines.push('      - 240.0.0.0/4')

    // 添加 Proxies 配置
    lines.push('')
    lines.push('proxies:')
    proxies.forEach(proxy => {
        const { address, remark } = proxy
        const [ip, port] = address.split(':')

        lines.push(`  - name: "${remark}"`)
        lines.push('    type: trojan')
        lines.push(`    server: ${ip}`)
        lines.push(`    port: ${port}`)
        lines.push(`    password: "${password}"`)
        lines.push('    udp: false')
        lines.push(`    sni: "${hostname}"`)
        lines.push('    network: ws')
        lines.push('    ws-opts:')
        lines.push('      path: "/?ed2560"')
        lines.push(`      headers:`)
        lines.push(`        Host: "${hostname}"`)
    })

    // 添加 Proxy Groups 配置
    lines.push('')
    lines.push('proxy-groups:')
    
    // 负载均衡
    lines.push('  - name: "负载均衡"')
    lines.push('    type: load-balance')
    lines.push('    strategy: consistent-hashing')
    lines.push('    url: http://www.gstatic.com/generate_204')
    lines.push('    interval: 180')
    lines.push('    proxies:') // 不使用引号
    proxies.forEach(p => {
        lines.push(`      - "${p.remark}"`) // 每个代理名称单独一行，并用引号包围
    })

    // 自动选择
    lines.push('')
    lines.push('  - name: "自动选择"')
    lines.push('    type: url-test')
    lines.push('    url: http://www.gstatic.com/generate_204')
    lines.push('    interval: 300')
    lines.push('    tolerance: 50')
    lines.push('    proxies:') // 不使用引号
    proxies.forEach(p => {
        lines.push(`      - "${p.remark}"`) // 每个代理名称单独一行，并用引号包围
    })

    // 选择代理
    lines.push('')
    lines.push('  - name: "选择代理"')
    lines.push('    type: select')
    lines.push('    proxies:')
    const allProxyNames = proxies.map(p => p.remark)
    const selectProxies = ['DIRECT', '负载均衡', '自动选择', ...allProxyNames] // 将 DIRECT 和其他代理组放在前面
    selectProxies.forEach(name => {
        lines.push(`      - "${name}"`)
    })

    // 添加 Rules 配置
    lines.push('')
    lines.push('rules:')
    lines.push('  - GEOIP,LAN,DIRECT')
    lines.push('  - GEOIP,CN,DIRECT')
    lines.push('  - MATCH,选择代理')

    return lines.join('\n')
}
