
const options = {server: ''};

chrome.storage.local.get('server').then((result) => {
    Object.assign(options, result);
    console.info(JSON.stringify(result));
});

async function handleMessageAsync(request, sendResponse){

    if(request.type === 'getCredential'){    
        var result = await fetch(options.server + '/shwmae/challenge', {
            method: "POST",
            body: request.value,
            headers: {
                "Content-type": "application/json; charset=UTF-8"
            }        
        });

        var assertions = await result.json();
        sendResponse(assertions[0]);

    }else if(request.type === 'save'){ 

        options.server = request.value;  
        chrome.storage.local.set(options);

    }else if(request.type == 'load'){    
        sendResponse(options);
    }        
}

function handleMessage(request, sender, sendResponse){
    handleMessageAsync(request, sendResponse)
    return true;
}

chrome.runtime.onMessage.addListener(handleMessage);
chrome.runtime.onMessageExternal.addListener(handleMessage);

