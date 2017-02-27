var http = require('http');
var url = require('url');
var net = require('net');
var EventEmitter = require('events').EventEmitter;
var inherits = require('util').inherits;
var inherits = require('util').inherits;

module.exports = {
  EventedHTTPClient: EventedHTTPClient
}

function EventedHTTPClient(host, port) {
  var that = this;
  this.host=host;
  this.port=port;
  
  this._session = null;
  this.SocketToAccessory = new net.Socket();
  this.SocketToAccessory.on('data', function (data) { HandleDecryptionFromAccessory(data); })
  this.SocketToAccessory.on('close', function (data) { console.log('Connection Closed'); });
  this.SocketToAccessory.connect(this.port, this.host, function () { console.log('Connected'); });
  this.SocketFromNode = null;
  this.listenerPort = 0;
  this.ListenerFromNode = net.createServer(function (sock) {
    if (that.SocketFromNode == null) {
      SetupSocketFromNode(sock)
      //sock.write('Im Listening.\n');
    } else {
      SetupSocketFromNode(sock)
      //sock.end('Im Full\n');
    }
    });

  function SetupSocketFromNode(sock) {
    that.SocketFromNode = sock;
    sock.on('end', function (data) { SocketFromNode = null; });
    sock.on('data', function (data) { HandleEncryptionToAccessory(data, that); })
    }

  function HandleDecryptionFromAccessory(data) {
    // give listeners an opportunity to decrypt this data before sending it to the client
    var decrypted = { data: null };
    that.emit('decrypt', data, decrypted, that._session);
    if (decrypted.data) data = decrypted.data;

    if (that.SocketFromNode != null) {
      that.SocketFromNode.write(data);
    } else {
      console.log(data);
    }
    //console.log('***OUT>>'+data.toString());

    }
  function HandleEncryptionToAccessory(data, that) {
    // give listeners an opportunity to encrypt this data before sending it to the client
    var encrypted = { data: null };
    that.emit('encrypt', data, encrypted, that._session);
    if (encrypted.data) data = encrypted.data;

    if (that.SocketToAccessory != null)
      that.SocketToAccessory.write(data);
    //console.log('***IN>>'+data.toString());
    }
  }

inherits(EventedHTTPClient, EventEmitter);

EventedHTTPClient.prototype.InitializeProxy = function(PairingData, setupCallback) {
    var that = this;
    this.session = PairingData;
    this.ListenerFromNode.listen(0, function () {
    that.listenerPort = this.address().port;
    console.log(that.listenerPort);
    setupCallback(PairingData);
    });
}
EventedHTTPClient.prototype.HTTPCommand = function (method, path, data, callback) {
    //"POST", "PUT", "GET", "DELETE"
    var options = {
      hostname: '127.0.0.1',
      port: this.listenerPort,
      path: path,
      method: method,
      headers: {}
      };

    var that = this;

    if (data) {
      options.headers['Host'] = 'test._hap._tcp.local';
      options.headers['Content-Length'] = Buffer.byteLength(data);
      options.headers['Content-Type'] = "application/pairing+tlv8";
      }

    var received;
    var req = http.request(options, function (response) {

      //Find the Content Type header
      //If the Content Type ends in tlv8 then
      response.on('data', function (chunk) {
        if (received == undefined)
          received = chunk;
        else
          received = Buffer.concat(received, chunk);
        });

      response.on('end', function () {
        response.data = received;
        if (callback) { callback(response); callback = undefined; };
        });
      });

    if (data) {
      req.write(data);
      }

    req.end();

    req.on('error', function (e) {
      console.log("error at req: ", e.message);
      if (callback) { callback(); callback = undefined; };
      });
  }





//EventedHTTPClient();
