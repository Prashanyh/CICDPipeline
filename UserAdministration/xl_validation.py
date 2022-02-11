def isInt_try(v):
    try:     i = int(v)
    except:  return False
    return True

def isInt_str(v):
    v = str(v).strip()
    return v=='0' or (v if v.find('..') > -1 else v.lstrip('-+').rstrip('0').rstrip('.')).isdigit()

def isInt_re(v):
    import re
    if not hasattr(isInt_re, 'intRegex'):
        isInt_re.intRegex = re.compile(r"^([+-]?[1-9]\d*|0)$")
    return isInt_re.intRegex.match(str(v).strip()) is not None