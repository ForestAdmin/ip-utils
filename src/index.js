const rangeCheck = require('range_check');
const { Address6 } = require('ip-address');

const TYPE_IP = 0;
const TYPE_RANGE = 1;
const TYPE_SUBNET = 2;

// NOTICE: Since IPs are 4 bytes, they can be converted to integers to be compared.
function ipV4ToInt(ip) {
  const bytes = ip.split('.');
  return ((((((+bytes[0]) * 256) + (+bytes[1])) * 256) + (+bytes[2])) * 256) + (+bytes[3]);
}

// NOTICE: IP v6 addresses are 128, it doesn't fit to an integer so we use BigInteger.
function ipV6ToBigInteger(ipv6) {
  const address = new Address6(ipv6);

  return address.bigInteger();
}

function processIP(rule) {
  if (rangeCheck.isIP(rule)) {
    const normalizedIp = rangeCheck.displayIP(rule);

    return {
      isValid: true,
      rule: {
        type: TYPE_IP,
        ip: normalizedIp,
      },
    };
  }

  return { isValid: false };
}

function processRange(rule) {
  const match = rule.match(/^(.*)-(.*)$/);

  if (!match) {
    return {
      isValid: false,
      match: false,
    };
  }

  const [, ip1, ip2] = match;

  if (!rangeCheck.isIP(ip1) || !rangeCheck.isIP(ip2)) {
    return { isValid: false };
  }

  const normalizedIp1 = rangeCheck.displayIP(ip1);
  const normalizedIp2 = rangeCheck.displayIP(ip2);

  const ipType1 = rangeCheck.ver(normalizedIp1);
  const ipType2 = rangeCheck.ver(normalizedIp2);

  if (ipType1 !== ipType2) {
    return {
      isValid: false,
      match: true,
      reason: 'Both IP must be the same version',
    };
  }

  if (ipType1 === 4) {
    const integerIp1 = ipV4ToInt(normalizedIp1);
    const integerIp2 = ipV4ToInt(normalizedIp2);

    if (integerIp1 > integerIp2) {
      return {
        isValid: false,
        match: true,
        reason: 'First IP higher than the second',
      };
    }
  } else {
    const integerIp1 = ipV6ToBigInteger(normalizedIp1);
    const integerIp2 = ipV6ToBigInteger(normalizedIp2);

    if (integerIp1.compareTo(integerIp2) > 0) {
      return {
        isValid: false,
        match: true,
        reason: 'First IP higher than the second',
      };
    }
  }

  return {
    isValid: true,
    rule: {
      type: TYPE_RANGE,
      ipMinimum: normalizedIp1,
      ipMaximum: normalizedIp2,
    },
  };
}

function processSubnet(rule) {
  const match = rule.match(/^(.*)\/(\d{1,3})$/);

  if (!match) {
    return {
      isValid: false,
      match: false,
    };
  }

  const [, ip, mask] = match;
  const maskNumber = parseInt(mask, 10);

  if (!rangeCheck.isIP(ip)) {
    return {
      isValid: false,
      match: true,
      reason: 'IP is invalid',
    };
  }

  const normalizedIp = rangeCheck.displayIP(ip);
  const ipVersion = rangeCheck.ver(normalizedIp);

  if (ipVersion === 4 && (maskNumber < 0 || mask > 32)) {
    return {
      isValid: false,
      match: true,
      reason: 'Mask must be between 0 and 32',
    };
  } else if (maskNumber < 0 || mask > 128) {
    return {
      isValid: false,
      match: true,
      reason: 'Mask must be between 0 and 128',
    };
  }

  return {
    isValid: true,
    rule: {
      type: TYPE_SUBNET,
      range: `${normalizedIp}/${mask}`,
    },
  };
}

function stringToRuleObject(ruleString) {
  const trimmedRule = ruleString.trim().replace(/ /g, '');

  let result = processIP(trimmedRule);
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
  const normalizedIp = rangeCheck.displayIP(ip);

  if (rule.type === TYPE_IP) {
    return normalizedIp === rule.ip;
  } else if (rule.type === TYPE_RANGE) {
    const ipVersion = rangeCheck.ver(normalizedIp);
    const rangeVersion = rangeCheck.ver(rule.ipMinimum);

    if (ipVersion !== rangeVersion) {
      return false;
    }

    if (ipVersion === 4) {
      const ipValueMinimum = ipV4ToInt(rule.ipMinimum);
      const ipValueMaximum = ipV4ToInt(rule.ipMaximum);
      const ipValue = ipV4ToInt(normalizedIp);

      return ipValue >= ipValueMinimum && ipValue <= ipValueMaximum;
    }

    const ipValueMinimum = ipV6ToBigInteger(rule.ipMinimum);
    const ipValueMaximum = ipV6ToBigInteger(rule.ipMaximum);
    const ipValue = ipV6ToBigInteger(normalizedIp);

    return ipValue.compareTo(ipValueMinimum) >= 0 && ipValue.compareTo(ipValueMaximum) <= 0;
  } else if (rule.type === TYPE_SUBNET) {
    return rangeCheck.inRange(normalizedIp, rule.range);
  }

  throw new Error('Invalid rule type');
}

function contain(list, ip) {
  return list.some((rule) => {
    const ruleObject = stringToRuleObject(rule.value);
    let matchFound = false;

    if (ruleObject.isValid) {
      matchFound = isIpMatchesRule(ip, ruleObject.rule);
    }

    return matchFound;
  });
}

module.exports = {
  checkRule: stringToRuleObject,
  contain,
};
