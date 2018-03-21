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

    describe('with a valid subnet "10.0.0.0/24"', () => {
      it('should return true', () => {
        const { isValid } = ipUtil.checkRule('10.0.0.0/24');

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

    describe('with an IPv6 IP "::1"', () => {
      it('should return the error "Only IPv4 is supported"', () => {
        const { isValid, reason } = ipUtil.checkRule('::1');

        expect(isValid).to.be.false;
        expect(reason).equal('Only IPv4 is supported');
      });
    });

    describe('with an IP with a byte out of range "10.0.0.300"', () => {
      it('should return the error "IP is invalid"', () => {
        const { isValid, reason } = ipUtil.checkRule('10.0.0.300');

        expect(isValid).to.be.false;
        expect(reason).equal('IP is invalid');
      });
    });

    describe('with a range with a the first IP invalid "10.0.0.300 - 10.0.1.20"', () => {
      it('should return the error "First IP is invalid"', () => {
        const { isValid, reason } = ipUtil.checkRule('10.0.0.300 - 10.0.1.20');

        expect(isValid).to.be.false;
        expect(reason).equal('First IP is invalid');
      });
    });

    describe('with a range with a the second IP invalid "10.0.0.1 - 10.0.0.300"', () => {
      it('should return the error "Second IP is invalid"', () => {
        const { isValid, reason } = ipUtil.checkRule('10.0.0.1 - 10.0.0.300');

        expect(isValid).to.be.false;
        expect(reason).equal('Second IP is invalid');
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
        value: '10.0.1.0/24',
      },
    ];

    describe('with an IP matching an IP rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.0.1');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP matching the first IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.0.10');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP matching the last IP of a range rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.0.15');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP matching the first IP of a subnet rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.1.1');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP matching the last IP of a subnet rule', () => {
      it('should return true', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.1.255');

        expect(isContained).to.be.true;
      });
    });

    describe('with an IP not matching any rule', () => {
      it('should return false', () => {
        const isContained = ipUtil.contain(ipWhitelistRules, '10.0.0.69');

        expect(isContained).to.be.false;
      });
    });
  });
});
