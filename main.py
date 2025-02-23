from surveyor import Surveyor

def entry(event, context=None):
    if not event.get("init"):
        return "Please provide init parameters"
    if not event.get("args"):
        return "Please provide survey parameters"
    
    return Surveyor(**event.get("init")).survey(**event.get("args"))