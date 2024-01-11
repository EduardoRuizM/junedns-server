//
// ================== JuNeDNS Server ==================
//
// Copyright (c) 2024 Eduardo Ruiz <eruiz@dataclick.es>
// https://github.com/EduardoRuizM/junedns-server
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE

// Install dependence: npm install mysql
// Test with: nslookup -type=soa dataclick.es 127.0.0.1

const fs = require('fs');
const path = require('path');
const dns2 = require('./lib');
const util = require('util');
const mysql = require('mysql');
const { Packet } = dns2;

const fcfg = process.cwd() + path.sep + 'junedns.conf';
const flog = process.cwd() + path.sep + 'junedns.log';

// Read and assign configuration
let log = 0, cfg = {};
try {

  fs.readFileSync(fcfg).toString().replace(/\r/g, '').split('\n').map(c => c).forEach(l => {
    l = l.split('=');
    if(l.length === 2)
      cfg[l[0].trim()] = l[1].trim();
  });

  log = cfg.log || 0;

  if(!cfg.mysql_name || !cfg.mysql_user || !cfg.mysql_pass)
    throw new Error('No database config');

} catch(err) {

  addLog(err, 1);
  process.exit(1);
}

cfg.protocol_ipv4 = !(cfg.protocol_ipv4 === 'false');
cfg.protocol_doh = (cfg.protocol_doh === 'true');
cfg.forward_pri_ip = (cfg.forward_pri_ipv6) ? cfg.forward_pri_ipv6 : cfg.forward_pri_ipv4 || '8.8.8.8';
cfg.forward_sec_ip = (cfg.forward_sec_ipv6) ? cfg.forward_sec_ipv6 : cfg.forward_sec_ipv4 || '8.8.4.4';

const dns = new dns2({nameServers: [cfg.forward_pri_ip, cfg.forward_sec_ip]});
const ipv4r = (cfg.ipv4 || '127.0.0.1').split('.').reverse().join('.') + '.in-addr.arpa';
const ipv6r = Packet.fromIPv6(cfg.ipv6 || '::1').map(n => n.padStart(4, 0)).join('').split('').reverse().join('.') + '.ip6.arpa';

// Database
const db = mysql.createConnection({host: cfg.mysql_host || '127.0.0.1', user: cfg.mysql_user, password: cfg.mysql_pass, database: cfg.mysql_name, port: cfg.mysql_port || 3306});
const query = util.promisify(db.query).bind(db);

// Functions
function addLog(txt, type, ip, action) {
  action = action || 'ERR';
  if(type === 1) {

    txt = (typeof txt === 'object') ? ((log == 3) ? txt.stack : txt.message) : txt;
    console.error('JuNeDNS', action, txt);
  }

  if(type > log)
    return;

  const d = (new Date()).toISOString().substring(0, 19).replace('T', ' ');
  try {

    if(fs.existsSync(flog) && fs.statSync(flog).size > 50 * 1024 * 1024)
      fs.writeFileSync(flog, '');

    ip = ip || '';
    txt = `${d} [${action}] IP: ${ip} ${txt}\n`;
    if(log == 3) //Debug
      console.log(txt);
    else
      fs.appendFileSync(flog, txt);

  } catch(e) {

    console.error('Unable to save log file', e.message);
  }
}

function trimDot(name) {
  return name.replace(/^\.+|\.+$/g, '');
}

// Root Zone default Second-level domain
function getRoot(name, depth) {
  depth = depth || 2;
  return name.split('.').slice(-depth).join('.');
}

// Main
const typenum = Object.fromEntries(Object.entries(Packet.TYPE).map(([k, v]) => [v, k]));
async function Request(request, send, ip, proto) {
  const response = Packet.createResponseFromRequest(request), ipp = `<${ip}> ${proto}`;
  if(log == 3)
    addLog(JSON.stringify(response), 2, ipp, 'REQ');

  try {

    for(let i = 0; i < request.questions.length; i++) {

      let question = request.questions[i], domain = getRoot(question.name), type = typenum[question.type], s;
      question.name = trimDot(question.name);
      if(question.type === 12 && cfg.main_domain && (ipv4r && question.name === ipv4r || question.name === ipv6r))
	domain = main_domain;

      const result = await query('SELECT * FROM domains WHERE name=? LIMIT 1', domain);
      if(result.length && type && 'A AAAA NS CNAME PTR MX SRV SPF TXT SOA CAA NAPTR TLSA '.indexOf(type + ' ') !== -1) {

	const records = await query('SELECT * FROM records WHERE domain_id=? AND name=? AND type=? AND disabled=0', [result[0].id, question.name, type]);
	for(let r of records) {

	  let a = {name: question.name, type: question.type, class: question.class, ttl: r.ttl};
	  switch(type) {
	    case 'SOA':
	      s = r.content.split(' ');
	      a.primary = s[0] || '';
	      a.admin = s[1] || '';
	      a.serial = s[2] || '';
	      a.refresh = s[3] || '';
	      a.retry = s[4] || '';
	      a.expiration = s[5] || '';
	      a.minimum = s[6] || '';
	      break;
	    case 'NS':
	      a.ns = r.content;
	      break;
	    case 'A':
	    case 'AAAA':
	      a.address = r.content;
	      break;
	    case 'PTR':
	    case 'CNAME':
	      a.domain = r.content;
	      break;
	    case 'MX':
	      s = r.content.split(' ');
	      a.exchange = s[0] || '';
	      a.priority = s[1] || '';
	      break;
	    case 'SRV':
	      s = r.content.split(' ');
	      a.priority = s[0] || '';
	      a.weight = s[1] || '';
	      a.port = s[2] || '';
	      a.target = s[3] || '';
	      break;
	    case 'CAA':
	      s = r.content.split(' ');
	      a.flags = s[0] || '';
	      a.tag = s[1] || '';
	      a.value = s[2] || '';
	      break;
	    case 'NAPTR':
	      s = r.content.split(' ');
	      a.order = s[0] || '';
	      a.preference = s[1] || '';
	      a.flags = s[2] || '';
	      a.service = s[3] || '';
	      a.regexp = s[4] || '';
	      a.replacement = s[5] || '';
	      break;
	    default:
	      a.data = r.content;
	      break;
	  }

	  response.answers.push(a);
	}

	if(log > 1)
	  addLog(((type) ? type : question.type) + ' ' + question.name + ' -> ' + JSON.stringify((log == 3) ? response : response.answers), 2, ipp, 'RES');

      } else {

	if(cfg.forward === 'true') {

	  const result = await dns.resolve(question.name, type);

	  if(log > 1)
	    addLog(((type) ? type : question.type) + ' ' + question.name + ' -> ' + JSON.stringify(result), 2, ipp, 'FWD');

	  for(const r in result.answers)
	    response.answers.push(result.answers[r]);
	}

	if(!response.answers.length && log && request.questions)
	  addLog(request.questions[0].name, 1, ipp, 'NXDOMAIN');
      }
    }

    send(response);

    if(cfg.protocol_dot && fs.existsSync(cfg.dot_cert) && dotcert_dt !== fs.statSync(cfg.dot_cert).mtime) {
      serverdot.close();
      server_dot();
    }

    if(cfg.protocol_doh && fs.existsSync(cfg.doh_cert) && dohcert_dt !== fs.statSync(cfg.doh_cert).mtime) {
      serverdoh.close();
      server_doh();
    }

  } catch(err) {

    addLog(err, 1, ipp);
  }
}

if(cfg.protocol_ipv4) {

  const server4 = dns2.createServer({
    udp: true,
    tcp: true,
    handle: (request, send, rinfo, proto) => {
      Request(request, send, rinfo.address, proto);
    }
  });

  server4.on('requestError', (err) => {
    addLog(err, 1);
  });

  server4.on('listening', () => {
    console.log('JuNeDNS Server on IPv4', server4.addresses());
  });

  server4.listen({udp: {address: '0.0.0.0', port: 53}, tcp: {address: '0.0.0.0', port: 53}});
}

let serverdot, dotcert_dt;
function server_dot() {
  dotcert_dt = fs.statSync(cfg.dot_cert).mtime;
  serverdot = dns2.createServer({
    dot: {cert: fs.readFileSync(cfg.dot_cert), key: fs.readFileSync(cfg.dot_key)},
    handle: (request, send, client, proto) => {
      Request(request, send, client.remoteAddress, proto);
    }
  });

  serverdot.on('error', (err, p) => {
    addLog(err, 1);
  });

  serverdot.on('listening', () => {
    console.log('JuNeDNS Server on DoT', serverdot.addresses());
  });

  serverdot.listen({dot: {address: '0.0.0.0', port: 853}});
}
if(cfg.protocol_dot && cfg.dot_cert && fs.existsSync(cfg.dot_cert) && cfg.dot_key && fs.existsSync(cfg.dot_key))
  server_dot();

let serverdoh, dohcert_dt;
function server_doh() {
  dohcert_dt = (fs.existsSync(cfg.doh_cert)) ? fs.statSync(cfg.doh_cert).mtime : 0;
  serverdoh = dns2.createServer({
    doh: (cfg.doh_cert && doh_key) ? {port: 443, ssl: true, cert: cfg.doh_cert, key: doh_key} : {port: cfg.doh_port},
    handle: (request, send, client, proto) => {
      Request(request, send, client.socket.remoteAddress, proto);
    }
  });

  serverdoh.on('error', (err, p) => {
    addLog(err, 1);
  });

  serverdoh.on('listening', () => {
    console.log('JuNeDNS Server on DoH', serverdoh.addresses());
  });

  serverdoh.listen();
}
if(cfg.protocol_doh)
  server_doh();
