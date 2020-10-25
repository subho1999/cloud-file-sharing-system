const {Transform} = require('stream')

class AppendInitVect extends Transform {
    constructor(initVector, opts) {
        super(opts)
        this.initVector = initVector
        this.appended = false
    }

    _transform(chunk, encoding, cb) {
        if (!this.appended) {
            this.push(this.initVector)
            this.appended = true
        }
        this.push(chunk);
        cb();
    }
}

module.exports = AppendInitVect