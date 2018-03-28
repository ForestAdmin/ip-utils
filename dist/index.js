'use strict';

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var rangeCheck = require('range_check');

var _require = require('ip-address'),
    Address6 = _require.Address6;

var TYPE_IP = 0;
var TYPE_RANGE = 1;
var TYPE_SUBNET = 2;

// NOTICE: Since IPs are 4 bytes, they can be converted to integers to be compared.
function ipV4ToInt(ip) {
  var bytes = ip.split('.');
  return ((+bytes[0] * 256 + +bytes[1]) * 256 + +bytes[2]) * 256 + +bytes[3];
}

// NOTICE: IP v6 addresses are 128, it doesn't fit to an integer so we use BigInteger.
function ipV6ToBigInteger(ipv6) {
  var address = new Address6(ipv6);

  return address.bigInteger();
}

function processIP(rule) {
  if (rangeCheck.isIP(rule)) {
    var normalizedIp = rangeCheck.displayIP(rule);

    return {
      isValid: true,
      rule: {
        type: TYPE_IP,
        ip: normalizedIp
      }
    };
  }

  return { isValid: false };
}

function processRange(rule) {
  var match = rule.match(/^(.*)-(.*)$/);

  if (!match) {
    return {
      isValid: false,
      match: false
    };
  }

  var _match = _slicedToArray(match, 3),
      ip1 = _match[1],
      ip2 = _match[2];

  if (!rangeCheck.isIP(ip1) || !rangeCheck.isIP(ip2)) {
    return { isValid: false };
  }

  var normalizedIp1 = rangeCheck.displayIP(ip1);
  var normalizedIp2 = rangeCheck.displayIP(ip2);

  var ipType1 = rangeCheck.ver(normalizedIp1);
  var ipType2 = rangeCheck.ver(normalizedIp2);

  if (ipType1 !== ipType2) {
    return {
      isValid: false,
      match: true,
      reason: 'Both IP must be the same version'
    };
  }

  if (ipType1 === 4) {
    var integerIp1 = ipV4ToInt(normalizedIp1);
    var integerIp2 = ipV4ToInt(normalizedIp2);

    if (integerIp1 > integerIp2) {
      return {
        isValid: false,
        match: true,
        reason: 'First IP higher than the second'
      };
    }
  } else {
    var _integerIp = ipV6ToBigInteger(normalizedIp1);
    var _integerIp2 = ipV6ToBigInteger(normalizedIp2);

    if (_integerIp.compareTo(_integerIp2) > 0) {
      return {
        isValid: false,
        match: true,
        reason: 'First IP higher than the second'
      };
    }
  }

  return {
    isValid: true,
    rule: {
      type: TYPE_RANGE,
      ipMinimum: normalizedIp1,
      ipMaximum: normalizedIp2
    }
  };
}

function processSubnet(rule) {
  var match = rule.match(/^(.*)\/(\d{1,3})$/);

  if (!match) {
    return {
      isValid: false,
      match: false
    };
  }

  var _match2 = _slicedToArray(match, 3),
      ip = _match2[1],
      mask = _match2[2];

  var maskNumber = parseInt(mask, 10);

  if (!rangeCheck.isIP(ip)) {
    return {
      isValid: false,
      match: true,
      reason: 'IP is invalid'
    };
  }

  var normalizedIp = rangeCheck.displayIP(ip);
  var ipVersion = rangeCheck.ver(normalizedIp);

  if (ipVersion === 4 && (maskNumber < 0 || mask > 32)) {
    return {
      isValid: false,
      match: true,
      reason: 'Mask must be between 0 and 32'
    };
  } else if (maskNumber < 0 || mask > 128) {
    return {
      isValid: false,
      match: true,
      reason: 'Mask must be between 0 and 128'
    };
  }

  return {
    isValid: true,
    rule: {
      type: TYPE_SUBNET,
      range: normalizedIp + '/' + mask
    }
  };
}

function stringToRuleObject(ruleString) {
  var trimmedRule = ruleString.trim().replace(/ /g, '');

  var result = processIP(trimmedRule);
  if (result.isValid || result.match) {
    return result;
  }

  result = processRange(trimmedRule);
  if (result.isValid || result.match) {
    return result;
  }

  result = processSubnet(trimmedRule);
  if (result.isValid || result.match) {
    return result;
  }

  return { isValid: false, reason: 'Badly constructed rule' };
}

function isIpMatchesRule(ip, rule) {
  var normalizedIp = rangeCheck.displayIP(ip);

  if (rule.type === TYPE_IP) {
    return normalizedIp === rule.ip;
  } else if (rule.type === TYPE_RANGE) {
    var ipVersion = rangeCheck.ver(normalizedIp);
    var rangeVersion = rangeCheck.ver(rule.ipMinimum);

    if (ipVersion !== rangeVersion) {
      return false;
    }

    if (ipVersion === 4) {
      var _ipValueMinimum = ipV4ToInt(rule.ipMinimum);
      var _ipValueMaximum = ipV4ToInt(rule.ipMaximum);
      var _ipValue = ipV4ToInt(normalizedIp);

      return _ipValue >= _ipValueMinimum && _ipValue <= _ipValueMaximum;
    }

    var ipValueMinimum = ipV6ToBigInteger(rule.ipMinimum);
    var ipValueMaximum = ipV6ToBigInteger(rule.ipMaximum);
    var ipValue = ipV6ToBigInteger(normalizedIp);

    return ipValue.compareTo(ipValueMinimum) >= 0 && ipValue.compareTo(ipValueMaximum) <= 0;
  } else if (rule.type === TYPE_SUBNET) {
    return rangeCheck.inRange(normalizedIp, rule.range);
  }

  throw new Error('Invalid rule type');
}

function contain(list, ip) {
  return list.some(function (rule) {
    var ruleObject = stringToRuleObject(rule.value);
    var matchFound = false;

    if (ruleObject.isValid) {
      matchFound = isIpMatchesRule(ip, ruleObject.rule);
    }

    return matchFound;
  });
}

module.exports = {
  checkRule: stringToRuleObject,
  contain: contain,
  isIpMatchesRule: isIpMatchesRule
};