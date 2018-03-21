const rangeCheck = require('range_check');

const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const rangeRegex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*-\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;
const subnetRegex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/;

const matchIp = rule => rule.match(ipRegex);
const matchRange = rule => rule.match(rangeRegex);
const matchSubnet = rule => rule.match(subnetRegex);

const IP_TYPE = 0;
const RANGE_TYPE = 1;
const SUBNET_TYPE = 2;

const isIpv6 = ip => rangeCheck.isIP(ip) && rangeCheck.ver(ip) === 6;

// NOTICE: Since IPs are 4 bytes, they can be converted to integers to be compared.
function ipToInt(ip) {
  const bytes = ip.split('.');
  return ((((((+bytes[0]) * 256) + (+bytes[1])) * 256) + (+bytes[2])) * 256) + (+bytes[3]);
}

function processIp(trimmedRule) {
  if (!rangeCheck.isIP(trimmedRule)) {
    return { isValid: false, reason: 'IP is invalid' };
  }

  if (rangeCheck.ver(trimmedRule) !== 4) {
    return { isValid: false, reason: 'Only IPv4 is supported' };
  }

  return {
    isValid: true,
    rule: {
      type: IP_TYPE,
      ip: trimmedRule,
    },
  };
}

function processRange(matchedRule) {
  const ipMinimum = matchedRule[1];
  const ipMaximum = matchedRule[2];

  if (!rangeCheck.isIP(ipMinimum)) {
    return { isValid: false, reason: 'First IP is invalid' };
  }

  if (!rangeCheck.isIP(ipMaximum)) {
    return { isValid: false, reason: 'Second IP is invalid' };
  }

  if (rangeCheck.ver(ipMinimum) !== 4) {
    return { isValid: false, reason: 'Only IPv4 is supported' };
  }

  if (rangeCheck.ver(ipMaximum) !== 4) {
    return { isValid: false, reason: 'Only IPv4 is supported' };
  }

  const valueMin = ipToInt(ipMinimum);
  const valueMax = ipToInt(ipMaximum);

  if (valueMin > valueMax) {
    return { isValid: false, reason: 'First IP higher than the second' };
  }

  if (valueMin === valueMax) {
    return {
      isValid: true,
      rule: {
        type: IP_TYPE,
        ip: ipMinimum,
      },
    };
  }

  return {
    isValid: true,
    rule: {
      type: RANGE_TYPE,
      ipMinimum,
      ipMaximum,
    },
  };
}

function processSubnet(matchedRule) {
  const range = matchedRule[0];
  const ip = matchedRule[1];
  const mask = parseInt(matchedRule[2], 10);

  if (!rangeCheck.isIP(ip)) {
    return { isValid: false, reason: 'IP is invalid' };
  }

  if (rangeCheck.ver(ip) !== 4) {
    return { isValid: false, reason: 'Only IPv4 is supported' };
  }

  if (mask < 0 || mask > 32) {
    return { isValid: false, reason: 'Mask must be between 0 and 32' };
  }

  return {
    isValid: true,
    rule: {
      type: SUBNET_TYPE,
      range,
    },
  };
}

function stringToRuleObject(ruleString) {
  const trimmedRule = ruleString.trim();

  let matchedRule = matchIp(trimmedRule);
  if (matchedRule) {
    return processIp(trimmedRule);
  }

  matchedRule = matchRange(trimmedRule);
  if (matchedRule) {
    return processRange(matchedRule);
  }

  matchedRule = matchSubnet(trimmedRule);
  if (matchedRule) {
    return processSubnet(matchedRule);
  }

  if (isIpv6(trimmedRule)) {
    return { isValid: false, reason: 'Only IPv4 is supported' };
  }

  return { isValid: false, reason: 'Badly constructed rule' };
}

function isIpMatchesRule(ip, rule) {
  if (rule.type === IP_TYPE) {
    return ip === rule.ip;
  } else if (rule.type === RANGE_TYPE) {
    const ipValueMinimum = ipToInt(rule.ipMinimum);
    const ipValueMaximum = ipToInt(rule.ipMaximum);
    const ipValue = ipToInt(ip);

    return ipValue >= ipValueMinimum && ipValue <= ipValueMaximum;
  } else if (rule.type === SUBNET_TYPE) {
    return rangeCheck.inRange(ip, rule.range);
  }

  throw new Error('Invalid rule type');
}

function contain(list, ip) {
  return list.some((rule) => {
    const ruleObject = stringToRuleObject(rule.value);

    if (ruleObject.isValid === false) {
      throw new Error(`Invalid rule: ${ruleObject.reason}`, rule);
    }

    if (isIpMatchesRule(ip, ruleObject.rule)) {
      return true;
    }

    return false;
  });
}

module.exports = {
  checkRule: stringToRuleObject,
  contain,
};
