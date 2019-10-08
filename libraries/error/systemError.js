class SystemError extends Error {
    constructor(...args){
        super(...args);
        this.code = args[0];
        this.statusCode = 500;
    }

    getErrorMessage (componentName) {
        const errMsg = {
            "SystemError": {
                "9999": "System error"
            },
        }

        console.log(errMsg[componentName][this.code], typeof errMsg[componentName][this.code])
        if (errMsg[componentName][this.code] === undefined) {
            return "system error";
        }
        return errMsg[componentName][this.code];
    }
}

module.exports = SystemError;