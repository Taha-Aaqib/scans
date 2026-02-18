module.exports = {
    isOpenCidrRange: function(cidr) {
        if (!cidr || typeof cidr !== 'string') return false;

        const trimmed = cidr.trim();
        return trimmed === '0.0.0.0/0' ||
               trimmed === '::/0' ||
               trimmed === '0.0.0.0';
    },
};