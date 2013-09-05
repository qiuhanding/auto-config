var WsHubs = ["A.ws.ndn.ucla.edu", "B.ws.ndn.ucla.edu", "C.ws.ndn.ucla.edu", "D.ws.ndn.ucla.edu", "E.ws.ndn.ucla.edu", "ndnucla-staging.dyndns.org"];

function selectRandomHub () {
    var rand = ((new Date()).getTime()) % WsHubs.length;
    return WsHubs[rand];
}
