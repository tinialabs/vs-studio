var fs = require("fs");
const fse = require("fs-extra");
const child_process = require("child_process");

if (fs.existsSync("./public/static")) {
  fs.rmdirSync("./public/static", { recursive: true });
}

if (fs.existsSync("./public/lib")) {
  fs.rmdirSync("./public/lib", { recursive: true });
}

fse.copySync("./node_modules/@tinialabs/vscode-web/dist", "./public/static");

fse.copySync("./node_modules/semver-umd", "./public/lib/semver-umd");
fse.copySync("./node_modules/vscode-oniguruma", "./public/lib/vscode-oniguruma");
fse.copySync("./node_modules/vscode-textmate", "./public/lib/vscode-textmate");

if(fs.existsSync('./public/static/extensions/vscode-fs-memfs')){
  fs.rmdirSync('./public/static/extensions/vscode-fs-memfs', { recursive: true })
}
child_process.execSync('git clone https://github.com/microsoft/vscode-web-playground.git  public/static/extensions/vscode-fs-memfs', {stdio: 'inherit'});
process.chdir('public/static/extensions/vscode-fs-memfs');

child_process.execSync('yarn', {stdio: 'inherit'});
child_process.execSync('yarn compile', {stdio: 'inherit'});

process.chdir('../../../..');

const packageJSON = fs.readFileSync(
  "./public/static/extensions/vscode-fs-memfs/package.json"
);
const extensions = [{ packageJSON: JSON.parse(packageJSON), extensionPath:  "vscode-fs-memfs"}]

const content = `var memfs=${JSON.stringify(extensions)}`;

fs.writeFileSync("./public/memfs.js", content);
