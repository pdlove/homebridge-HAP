var storage = require('node-persist');

var path = require('path');
//var webclient = require('./util/webclient').webclient;
var pairing = require('./HAPPairing').HAPtoAccessoryPairing;
var PairingData = require('./HAPPairing').AccessoryData;
var uuid = require('./util/uuid');
var inherits = require('util').inherits;
//inherits(HAPServer, EventEmitter);



    //Test Code
//
var myData

function GetInformationFrom_MDNS(ServiceName, PairingData) {
	PairingData.my_username = uuid.generate('hap-nodejs:client:'+ServiceName),
	PairingData.acc_mdnsname=ServiceName;
	PairingData.acc_lastip='127.0.0.1';
	PairingData.acc_lastport=52702;
    PairingData.acc_pin='254-21-815';
    }


storage.initSync({dir: path.join((process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE),'.hap-persist')});
var newPair = storage.getItemSync('test.json');
var myPairing = new pairing(); 
PairingData.PairProcess = myPairing;
if (newPair===undefined) {
    GetInformationFrom_MDNS('test', PairingData);
    //PairingData.acc_pin='254-21-815';
    myPairing.PairAccessory(PairingData);
} else {
    newPair.my_privateKey=Buffer(newPair.my_privateKey.data);
    newPair.my_publicKey=Buffer(newPair.my_publicKey.data);
    newPair.acc_publicKey=Buffer(newPair.acc_publicKey.data);
    newPair.acc_username=Buffer(newPair.acc_username.data);
    PairingData=newPair;
    myPairing.VerifyAccessoryPairing(PairingData);
}

