const { expect } = require('chai');
const ipUtil = require('../src');

describe('Utils > IP Utils', () => {
  describe('Check rule validity', () => {
    describe('with a valid IP "10.0.0.1"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('10.0.0.1');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid IP "::1"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('::1');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid IP "2001:0db8:0000:0000:0000:ff00:0042:8329"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('2001:0db8:0000:0000:0000:ff00:0042:8329');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid IP "2001:db8::ff00:42:8329"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('2001:db8::ff00:42:8329');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid range "10.0.0.1-10.0.0.2"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('10.0.0.1-10.0.0.2');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid range "10.0.0.1 -10.0.0.2"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('10.0.0.1 -10.0.0.2');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid range "10.0.0.1- 10.0.0.2"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('10.0.0.1- 10.0.0.2');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid range "10.0.0.1 - 10.0.0.2"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('10.0.0.1 - 10.0.0.2');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid range "   10.0.0.1 - 10.0.0.2    "', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('   10.0.0.1 - 10.0.0.2    ');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid range "10.0.0.0 - 10.0.255.255"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('10.0.0.0 - 10.0.255.255');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid range "2001:0000:0000:0000:0000:0000:0000:0001-2001:0000:0000:0000:0000:0000:0000:0002"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('2001:0000:0000:0000:0000:0000:0000:0001-2001:0000:0000:0000:0000:0000:0000:0002');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid range "2001::1-2001::2"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('2001::1-2001::2');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid range "2001:0000:0000:0000:0000:0000:0000:0002-2001:0001:0000:0000:0000:0000:0000:0001"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('2001:0000:0000:0000:0000:0000:0000:0002-2001:0001:0000:0000:0000:0000:0000:0001');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid range "2001::2-2001:1::1"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('2001::2-2001:1::1');

        expect(isValid).to.be.true;
      });
    });

    describe('with a invalid range "2001:0001:0000:0000:0000:0000:0000:0001-2001:0000:0000:0000:0000:0000:0000:0002"', () => {
      it('should return false', () => {
        const { isValid } = ipUtil.checkRule('2001:0001:0000:0000:0000:0000:0000:0001-2001:0000:0000:0000:0000:0000:0000:0002');

        expect(isValid).to.be.false;
      });
    });

    describe('with a invalid range "2001:1::0001-2001::2"', () => {
      it('should return false', () => {
        const { isValid } = ipUtil.checkRule('2001:1::0001-2001::2');

        expect(isValid).to.be.false;
      });
    });

    describe('with mixed IPv4/IPv6 "127.0.0.1-::2"', () => {
      it('should return false and the message "Both IP must be the same version"', () => {
        const { isValid, reason } = ipUtil.checkRule('127.0.0.1-::2');

        expect(isValid).to.be.false;
        expect(reason).equal('Both IP must be the same version');
      });
    });

    describe('with a valid subnet "10.0.0.0/24"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('10.0.0.0/24');

        expect(isValid).to.be.true;
      });
    });

    describe('with a valid subnet "::1/120"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('::1/120');

        expect(isValid).to.be.true;
      });
    });

    describe('with a badly constructed ip "10.0.0."', () => {
      it('should return the error "Badly constructed rule"', () => {
        const { isValid, reason } = ipUtil.checkRule('10.0.0.');

        expect(isValid).to.be.false;
        expect(reason).equal('Badly constructed rule');
      });
    });

    describe('with an IP with a byte out of range "10.0.0.300"', () => {
      it('should return the error "Badly constructed rule"', () => {
        const { isValid, reason } = ipUtil.checkRule('10.0.0.300');

        expect(isValid).to.be.false;
        expect(reason).equal('Badly constructed rule');
      });
    });

    describe('with a range with a the first IP invalid "10.0.0.300 - 10.0.1.20"', () => {
      it('should return the error "Badly constructed rule"', () => {
        const { isValid, reason } = ipUtil.checkRule('10.0.0.300 - 10.0.1.20');

        expect(isValid).to.be.false;
        expect(reason).equal('Badly constructed rule');
      });
    });

    describe('with a range with a the second IP invalid "10.0.0.1 - 10.0.0.300"', () => {
      it('should return the error "Badly constructed rule"', () => {
        const { isValid, reason } = ipUtil.checkRule('10.0.0.1 - 10.0.0.300');

        expect(isValid).to.be.false;
        expect(reason).equal('Badly constructed rule');
      });
    });

    describe('with a range with first IP higher than the second "10.0.0.2 - 10.0.0.1"', () => {
      it('should return the error "First IP higher than the second"', () => {
        const { isValid, reason } = ipUtil.checkRule('10.0.0.2 - 10.0.0.1');

        expect(isValid).to.be.false;
        expect(reason).equal('First IP higher than the second');
      });
    });

    describe('with a subnet with an IP with a byte out of range "10.0.256.2/24"', () => {
      it('should return the error "IP is invalid"', () => {
        const { isValid, reason } = ipUtil.checkRule('10.0.256.2/24');

        expect(isValid).to.be.false;
        expect(reason).equal('IP is invalid');
      });
    });

    describe('with a subnet with a mask out of range "10.0.0.1/33"', () => {
      it('should return the error "Mask must be between 0 and 32"', () => {
        const { isValid, reason } = ipUtil.checkRule('10.0.0.1/33');

        expect(isValid).to.be.false;
        expect(reason).equal('Mask must be between 0 and 32');
      });
    });

    describe('with a subnet with a mask out of range "::1/129"', () => {
      it('should return the error "Mask must be between 0 and 128"', () => {
        const { isValid, reason } = ipUtil.checkRule('::1/129');

        expect(isValid).to.be.false;
        expect(reason).equal('Mask must be between 0 and 128');
      });
    });
  });

  describe('Check isIpMatchesRule function', () => {
    it('With range "90.88.0.0 - 90.88.255.255"', () => {
      const rule = {
        type: 1,
        ipMinimum: '90.88.0.0',
        ipMaximum: '90.88.255.255',
      };

      const isMatching = ipUtil.isIpMatchesRule('90.88.118.79', rule);

      expect(isMatching).to.be.true;
    });

    it('With range "90.88.0.1 - 90.88.255.255"', () => {
      const rule = {
        type: 1,
        ipMinimum: '90.88.0.1',
        ipMaximum: '90.88.255.255',
      };

      const isMatching = ipUtil.isIpMatchesRule('90.88.118.79', rule);

      expect(isMatching).to.be.true;
    });

    it('With range "90.88.0.1 - 90.88.254.254"', () => {
      const rule = {
        type: 1,
        ipMinimum: '90.88.0.1',
        ipMaximum: '90.88.254.254',
      };

      const isMatching = ipUtil.isIpMatchesRule('90.88.118.79', rule);

      expect(isMatching).to.be.true;
    });
  });

  describe('Check range inclusion', () => {
    const ipWhitelistRules = [
      {
        name: 'Work',
        value: '10.0.0.1',
      },
      {
        name: 'Work',
        value: '10.0.0.10 - 10.0.0.15',
      },
      {
        name: 'Work',
        value: '20.0.0.1 - 20.0.1.254',
      },
      {
        name: 'Work',
        value: '30.0.0.0 - 30.0.1.255',
      },
      {
        name: 'Work',
        value: '90.88.0.1 - 90.88.254.254',
      },
      {
        name: 'Work',
        value: '10.0.1.0/24',
      },
      {
        name: 'Work 2',
        value: '2001:0000:0000:0000:0000:0000:0000:0001',
      },
      {
        name: 'Work 3',
        value: '2001::2',
      },
      {
        name: 'Work 4',
        value: '2001:0000:0000:0000:0000:0000:0001:0001-2001:0000:0000:0000:0000:0001:0000:0001',
      },
      {
        name: 'Work 3',
        value: '2001:1::1-2001:1::1:1',
      },
      {
        name: 'Work 4',
        value: '4000::1100/120',
      },
    ];

    describe('with an IP "10.0.0.1" matching an IP rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.0.1');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "20.0.1.10" matching an IP rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '20.0.1.10');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "30.0.1.10" matching an IP rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '30.0.1.10');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "90.88.118.79" matching an IP rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '90.88.118.79');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001:0000:0000:0000:0000:0000:0000:0001" matching an IP rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001:0000:0000:0000:0000:0000:0000:0001');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001::1" matching an IP rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001::1');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001:0000:0000:0000:0000:0000:0000:0002" matching an IP rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001:0000:0000:0000:0000:0000:0000:0002');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001::2" matching an IP rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001::2');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "10.0.0.10" matching the first IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.0.10');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "10.0.0.15" matching the last IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.0.15');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001:0000:0000:0000:0000:0000:0001:0001" matching the first IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001:0000:0000:0000:0000:0000:0001:0001');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001::1:1" matching the first IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001::1:1');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001:0000:0000:0000:0000:0001:0000:0001" matching the last IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001:0000:0000:0000:0000:0001:0000:0001');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001::1:0000:1" matching the last IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001::1:0000:1');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001:0000:0000:0000:0000:0000:1111:0001" matching an IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001:0000:0000:0000:0000:0000:1111:0001');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001::1111:1" matching an IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001::1111:1');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001:1::1" matching the first IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001:1::1');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001:0001:0000:0000:0000:0000:0000:0001" matching the first IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001:0001:0000:0000:0000:0000:0000:0001');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001:1::1:1" matching the last IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001:1::1:1');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "2001:0001:0000:0000:0000:0000:0001:0001" matching the last IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '2001:0001:0000:0000:0000:0000:0001:0001');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "10.0.1.1" matching the first IP of a subnet rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.1.1');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "10.0.1.255" matching the last IP of a subnet rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.1.255');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "4000::1101" matching the first IP of a subnet rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '4000::1101');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "4000::11FF" matching the last IP of a subnet rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '4000::11FF');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "4000:0000:0000:0000:0000:0000:0000:1101" matching the first IP of a subnet rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '4000:0000:0000:0000:0000:0000:0000:1101');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "4000:0000:0000:0000:0000:0000:0000:11FF" matching the last IP of a subnet rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '4000:0000:0000:0000:0000:0000:0000:11FF');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP "10.0.0.69" not matching any rule', () => {
      it('should return false', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.0.69');

        expect(isContained).to.be.false;
      });
    });

    describe('with an IP "3000:0000:0000:0000:0000:0000:0000:0001" not matching any rule', () => {
      it('should return false', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '3000:0000:0000:0000:0000:0000:0000:0001');

        expect(isContained).to.be.false;
      });
    });

    describe('with an IP "3000::2" not matching any rule', () => {
      it('should return false', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '3000::2');

        expect(isContained).to.be.false;
      });
    });
  });
});
