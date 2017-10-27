//////////
// JNLP //
//////////

$("#enviarJNLP").click(function () {
    var id = [];
    $.each($("input[name='arqjnlp']:checked"), function(){
    	id.push($(this).val());
    });
    
    $.get("api/token/generate/" + id, function (data) {
        $("#hash").val(data);
        $('#jnlpForm').submit();
        $.blockUI({ message: "Aguardando assinaturas..." });
        verificarToken(data);
    });

});

function verificarToken(token){
 	console.warn("token: " + token);
    
 	$.blockUI({ message: "Verificando token..." });
 	var refreshId = setInterval(function(){
 	    $.ajax({ 
 	    	type:"GET",
            cache: false,
            url:  "api/token/validate/" + token,
            success: function(data){
                if (data == 'true') 
                	console.warn(data);
                else {
                	$.unblockUI();
                	alert("Assinatura verificada com sucesso!");
                	clearInterval(refreshId);
                }
            }
 	   });
 	}, 5000);
 	
 	window.setTimeout(function() {
 	    clearInterval(refreshId);
 	    $.unblockUI();
 	}, 60000);
}

//////////////////////
// Assinador SERPRO //
//////////////////////

$("#enviarAS").click(function () {
    var id = [];
    $.each($("input[name='arquivo']:checked"), function(){
    	console.log($(this).val());
    	id.push($(this).val());
    });
    
    $.get("api/filemanager/generateHashes/" + id, function (data) {
    	var hashes = '';
    	$.each(data, function(key, value) {
    		hashes += value;
    		hashes += ', ';
    	});
    	hashes = hashes.substring(0, hashes.length-2);
    	$("#hashes").val(hashes);
    	signQueue(id, data);
    	resetDetails();
    });

});

function signQueue(ids, idHashes) {
	console.log('idHashes');
	console.log(idHashes);
	if (ids.length > 0) {
		var id = ids.shift();
		var hash = idHashes[id];
		sign({
			type: 'hash',
			data: hash,
			onSuccess: function(result) {
				console.log("TUDO CERTO");
				console.log(result);
				signQueue(ids, idHashes);
			},
			onError: function (msg) {
				console.log("ERRO");
				console.log(msg);
				alert(msg.error);
	        },
	        afterSign: showResult,
	        fileName: id, 
	        // optional
			onCancel: resetDetails
			// beforeSign: beforeSignHandler, // optional
			// afterSign: afterSignHandler // optional
		});
	}
}

function sign(params) {
	// Valida os parâmetros obrigatórios
	if (!params.type) {
		throw new Error('Sign type is not defined.');
	}
	if (!params.data && params.type !== 'file') {
		throw new Error('Sign data is not defined.');
	}

	// Antes de assinar
	params.beforeSign && params.beforeSign();

	// Sign - Chama o assinador
	window.SerproSignerClient.sign(params.type, params.data)
		.success(function (response) {
			if (response.actionCanceled) {
				console.debug('Action canceled by User.');
				params.onCancel && params.onCancel(response);
			} else {
				console.debug('Sucesso:', response);
				params.onSuccess && params.onSuccess({
					original: {
						size: response.original.length,
						base64: response.original
					},
					signature: {
						size: response.signature.length,
						base64: response.signature
					}
				});
			}
			params.afterSign && params.afterSign(params.fileName, response);
		})
		.error(function (error) {
			console.debug('Error:', error);
			params.onError && params.onError(error);
			params.afterSign && params.afterSign(error);
		});
}

function showResult(fileName, data) {
	var signature = data.signature;
	if (signature) {
		var result = [
			'Arquivo: ' + fileName,
			'Base64: ' + signature
		].join('\n');
		appendToDetails(result);
	}
}

function appendToDetails(text) {
	var $asDetails = $('#assinador details');
	var $content = $asDetails.find('textarea');
	if ($content.val().length == 0) {
		$content.text($content.val() + text);
	} else {
		$content.text($content.val() + '\n\n' + text);
	}
	$asDetails.show();
}

function resetDetails() {
	//$("#hashes").val('');
	var $asDetails = $('#assinador details');
	var $content = $asDetails.find('textarea');
	$content.text('');
	$asDetails.hide();
}
