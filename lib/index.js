// Copyright (c) 2024 Eduardo Ruiz <eruiz@dataclick.es>
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
// THE SOFTWARE.

const udp = require('dgram');
const tcp = require('net');
const tls = require('tls')
const https = require('https');
const DOHServer = require('./doh');
const Packet = require('./packet');
const EventEmitter = require('events');
const { version } = require('../package.json');

class UDPServer extends udp.Socket {
  constructor(options) {
    let type = 'udp4';
    if(typeof options === 'object')
      type = options.type;

    super(type);
    this.on('message', this.handle.bind(this));
  }

  handle(data, rinfo) {
    try {
      const message = Packet.parse(data);
      this.emit('request', message, this.response.bind(this, rinfo), rinfo, 'UDP');
    } catch(e) {
      this.emit('requestError', e);
    }
  }

  response(rinfo, message) {
    if(message instanceof Packet)
      message = message.toBuffer();

    return new Promise((resolve, reject) => {
      this.send(message, rinfo.port, rinfo.address, err => {
	if(err) return reject(err);
	resolve(message);
      });
    });
  }

  listen(port, address) {
    return new Promise(resolve => this.bind(port, address, resolve));
  }
}

class TCPServer extends tcp.Server {
  constructor(options) {
    super();
    this.on('connection', this.handle.bind(this));
  }

  async handle(client) {
    try {
      const data = await Packet.readStream(client);
      const message = Packet.parse(data);
      this.emit('request', message, this.response.bind(this, client), client, 'TCP');
    } catch(e) {
      this.emit('requestError', e);
      client.destroy();
    }
  }

  response(client, message) {
    if(message instanceof Packet)
      message = message.toBuffer();

    const len = Buffer.alloc(2);
    len.writeUInt16BE(message.length);
    client.end(Buffer.concat([len, message]));
  }
}

class TLSServer extends tls.Server {
  constructor(options, listener) {
    super(options);
    this.on('secureConnection', this.handle.bind(this));
  }

  handle(client) {
    client.on('data', (data) => {
      const message = Packet.parse(Buffer.from(data, 'ascii'));
      this.emit('request', message, this.response.bind(this, client), client, 'DoT');
    });
  }

  response(client, message) {
    if(message instanceof Packet)
      message = message.toBuffer();

    const len = Buffer.alloc(2);
    len.writeUInt16BE(message.length);
    client.write(Buffer.concat([len, message]));
  }

  listen(port, address) {
    super.listen(port, address);
  }
}

class DNSServer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.servers = {};
    if(options.udp)
      this.servers.udp = (new UDPServer((typeof options.udp === 'object') ? options.udp : undefined)).on('error', error => this.emit('error', error, 'udp'));

    if(options.tcp)
      this.servers.tcp = (new TCPServer()).on('error', error => this.emit('error', error, 'tcp'));

    if(options.dot)
      this.servers.dot = (new TLSServer(options.dot)).on('error', error => this.emit('error', error, 'dot'));

    if(options.doh)
      this.servers.doh = (new DOHServer(options.doh)).on('error', error => this.emit('error', error, 'doh'));

    const servers = Object.values(this.servers);
    this.closed = Promise.all(
      servers.map(server => new Promise(resolve => server.once('close', resolve))),
    ).then(() => {
      this.emit('close');
    });

    this.listening = Promise.all(
      servers.map(server => new Promise(resolve => server.once('listening', resolve))),
    ).then(() => {
      const addresses = this.addresses();
      this.emit('listening', addresses);
      return addresses;
    });

    const emitRequest = (request, send, client, proto) => this.emit('request', request, send, client, proto);
    const emitRequestError = (error) => this.emit('requestError', error);
    for(const server of servers) {
      server.on('request', emitRequest);
      server.on('requestError', emitRequestError);
    }

    if(options.handle)
      this.on('request', options.handle.bind(options));
  }

  addresses() {
    const addresses = {};
    const { udp, tcp, dot, doh } = this.servers;
    if(udp)
      addresses.udp = udp.address();

    if(tcp)
      addresses.tcp = tcp.address();

    if(dot)
      addresses.dot = dot.address();

    if(doh)
      addresses.doh = doh.address();

    return addresses;
  }

  listen(options = {}) {
    for(const serverType of Object.keys(this.servers)) {
      const server = this.servers[serverType];
      const serverOptions = options[serverType]; // Port or {port, address}
      if(serverOptions && serverOptions.port)
	server.listen(serverOptions.port, serverOptions.address);
      else
	server.listen(serverOptions);
    }

    return this.listening;
  }

  close() {
    const { udp, tcp, dot, doh } = this.servers;
    if(udp)
      udp.close();

    if(tcp)
      tcp.close();

    if(dot)
      dot.close();

    if(doh)
      doh.close();

    return this.closed;
  }
}

class DNS extends EventEmitter {
  constructor(options) {
    super();
    Object.assign(this, options);
  }

  query(name, type, cls, clientIp) {
    return Promise.race(this.nameServers.map(address => {
      const resolve = DNS.UDPClient({dns: address, port: 53, recursive: true});
      return resolve(name, type, cls, clientIp);
    }));
  }

  resolve(domain, type = 'ANY', cls = DNS.Packet.CLASS.IN, clientIp = undefined) {
    return this.query(domain, type, cls, clientIp);
  }
}

DNS.createServer = options => {
  return new DNSServer(options);
}

DNS.UDPClient = require('./client');
DNS.Packet = require('./packet');

https.get(`https://junedns.com/latest.html?v=${version}`, r => {
  r.on('data', s => {
    s = s.toString().substring(0, 30).trim();
    if(s && version != s)
      console.log(`New available version ${s}`);
  });
}).on('error', e => e);

module.exports = DNS;
