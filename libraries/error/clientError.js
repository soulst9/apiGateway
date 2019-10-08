class ClientError extends Error {
    constructor(...args) {
        super(...args);
        this.code = args[0];
        this.statusCode = args[1] || 400;
        this.target = args[2];
        this.message = this.getErrorMessage(this.constructor.name);
    }

    getErrorMessage (componentName) {
        const errMsg = {
            "ClientError": {
                "0000": "Parameters include banned words",
                "0001": "Failed to authenticate token.",
                "0002": "No token provided",
                "0003": "Forbidden"
            },        
        }

        if (errMsg[componentName][this.code] === undefined) {
            return "unknown error";
        }
        return errMsg[componentName][this.code];
    }
}

module.exports = ClientError;