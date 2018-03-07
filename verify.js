// code form "An Introduction to the Bitcoin System"
//            https://www.gitbook.com/book/pascalpares/implementation-of-the-bitcoin-system/details

const crypto=require('crypto')
var   request = require("request");
// Calculate a hash code from a binary buffer
var sha256= function(buffer) { 
    var f = crypto.createHash('sha256'); 
    var h = f.update(buffer);
    return h.digest(); 
};

var serializeHeader = function (header) {
  var buffers = [];
  buffers.push (numberToInt32LE(header.version));
  buffers.push (hexaNotationToInt256LE(header.previousToken));
  buffers.push (hexaNotationToInt256LE(header.merkleRootHash));  
  buffers.push (dateToInt32LE(header.time));    
  buffers.push (numberToInt32LE(header.bits));  
  buffers.push (numberToInt32LE(header.nonce));    
  return Buffer.concat (buffers);
};
var numberToInt32LE = function (n) {
    var buffer = new Buffer(4);
    buffer.writeUInt32LE(n,0);
    return buffer;
};
var dateToInt32LE = function (date) {
    var time = date.getTime() / 1000; // remove milliseconds
    return numberToInt32LE(time);
};
var hexaNotationToInt256LE = function (hexa) {
    var bytes = new Array(32);
    for (var i = 0, j = 31, len = hexa.length; i < len; i+=2, j--) {
        bytes[j] = parseInt(hexa[i]+hexa[i+1],16);
    }    
    return new Buffer(bytes);
};

Buffer.prototype.toReverseHexaNotation = function () {
    var hexa = "";
    for (var i = this.length-1; i >= 0; i--) {
        var digits =  this[i].toString(16);
        hexa += ("0" + digits).slice(-2); // Add "0" for single digit
    }
    return hexa;     
};

// Header from block 125552
var header = {
    version: 1,
    previousToken: '00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81',
    merkleRootHash: '2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3',
    time: new Date ("Sat May 21 2011 17:26:31 GMT+0000 (UTC)"),
    bits: 440711666,
    nonce: 2504433986
};
var hashcode = sha256( sha256(serializeHeader(header)) ); // hash twice
console.log( hashcode.toReverseHexaNotation() )
