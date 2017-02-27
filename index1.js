

var Service, Characteristic, Accessory, uuid, EnergyCharacteristics;

var HomeKitAccessory;

module.exports = function (homebridge) {
	Service = homebridge.hap.Service;
	Characteristic = homebridge.hap.Characteristic;
	Accessory = homebridge.hap.Accessory;
	uuid = homebridge.hap.uuid;

	//SmartThingsAccessory = require('./accessories/smartthings')(Accessory, Service, Characteristic, uuid);

	homebridge.registerPlatform("homebridge-HAP", "HAP", HomeKitPlatform);
};

function HomeKitPlatform(log, config) {
	// Load Wink Authentication From Config File
	this.app_url = config["app_url"];
	this.app_id = config["app_id"];
	this.access_token = config["access_token"];
	
    //This is how often it does a full refresh
    this.polling_seconds = config["polling_seconds"];
	if (!this.polling_seconds) this.polling_seconds=60;
    
	this.log = log;
	this.deviceLookup = {};
    this.firstpoll = true;
    this.attributeLookup = {}
}

SmartThingsPlatform.prototype = {
	reloadData: function (callback) {
		//Loop through All Devices and reload the data from their Accessories Flag
},
	accessories: function (callback) {
		this.log("Fetching Smart Things devices.");
		
		var that = this;
		var foundAccessories = [];
		this.deviceLookup = [];
		
		//smartthings.init(this.app_url, this.app_id, this.access_token);
		//loop through devices

	}
	
};