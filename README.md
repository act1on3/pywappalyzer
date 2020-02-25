# Description

Python implementation of [wappalyzer extension](https://github.com/AliasIO/wappalyzer/blob/master/src/wappalyzer.js).

Supported checks:
- analyzeUrl
- analyzeHtml
- analyzeMeta
- analyzeCookies
- analyzeHeaders

Non-supported checks (the tool works w/o headless browser):
- analyzeScripts
- analyzeJs

# Usage
Just execute the script: `python3 wappalyzer/wappalyzer.py https://exmaple.com`