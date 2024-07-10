

async function refreshCreds(server){

    $('#cred-holder').empty();

    var result =  await fetch(server + '/shwmae/keys', {
        method: "GET",    
    });

    if(result.status == 200){
        var creds = await result.json();

        for(const cred of creds){
            $('#cred-holder').append(` 
                <div class="col-sm-12 p-1" >              
                    <div class="card">
                        <a class="card-block stretched-link text-decoration-none" href="https://${cred.rpId}" target="_blank">
                            <div class="card-header text-white bg-secondary">
                                <div class="col-sm-4">
                                    <div class="row">
                                        <img width="32px" height="32px" class="p-1" src="passkeys.png"/>${cred.rpId} (${cred.signCount})
                                    </div>
                                </div>
                            </div>
                            <div class="card-body bg-light">
                                <h5 class="card-title">Username: ${cred.username}</h5><h6 class="card-subtitle mb-2 text-muted">Credential Id:${cred.credentialId}</h6>
                            </div>
                        </a>
                    </div>
                </div>
            `);
        }        
    } 
}


$( document ).ready(function() {

    $("#options").on("submit", function(){
        chrome.runtime.sendMessage({type:'save', value: $('#server').val()});
        refreshCreds($('#server').val());
        return false;
    });

    chrome.runtime.sendMessage({type:'load'}, function(response){
        $('#server').val(response.server);
        if(response.server != null && response.server !== '')
            refreshCreds(response.server);
    });     
    
});

