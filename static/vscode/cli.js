"use strict";const bootstrap=require("./bootstrap"),bootstrapNode=require("./bootstrap-node"),product=require("../product.json");bootstrap.avoidMonkeyPatchFromAppInsights(),bootstrapNode.configurePortable(product),bootstrap.enableASARSupport(void 0),process.env.VSCODE_CLI="1",require("./bootstrap-amd").load("vs/code/node/cli");

//# sourceMappingURL=cli.js.map
