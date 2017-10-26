(function () {
	console.log('Arquivo example.js');

	// common vars handle ws server status
	var $serverStatus = $('.js-server-status');
	$serverStatus.hide();

	checkEnvironment();
	initApp();
	initSerproSignerClient();

	function initSerproSignerClient() {
		var timeoutDefault = 3000;
		var tryAgainTimeoutWebSocket;
		var tryAgainTimeoutVerify;

		// Configure SerproSigner
		configureDesktopClient();

		// Verify if is installed AND running
		// optional:
		verifyDesktopClientInstallation();

		// connect DIRECT to WebSocket
		// connectToWebSocket();

		function configureDesktopClient() {
			window.SerproSignerClient.setDebug(true);
			window.SerproSignerClient.setUriServer("wss", "127.0.0.1", 65156, "/signer");
		}

		function verifyDesktopClientInstallation() {
			window.SerproSignerClient.verifyIsInstalledAndRunning()
				.success(function (response) {
					clearInterval(tryAgainTimeoutVerify);
					connectToWebSocket();
				}).error(function (response) {
					console.log("verifyDesktopClientInstallation ERRO");
					showStatusOff();

					// Try again in Xms
					clearInterval(tryAgainTimeoutVerify);
					tryAgainTimeoutVerify = setTimeout(verifyDesktopClientInstallation, timeoutDefault);
				});
		}

		function connectToWebSocket() {
			window.SerproSignerClient.connect(callbackOpenClose, callbackOpenClose, callbackError);
		}

		function callbackOpenClose(connectionStatus) {

			if (connectionStatus === 1) {
				console.log('Connected on Server');
				showStatusOn();

				clearInterval(tryAgainTimeoutWebSocket);
			} else {
				console.log('Warn user to download/execute Agent-Desktop AND try again in ' + timeoutDefault + 'ms');
				showStatusOff();

				// Try again in Xms
				clearInterval(tryAgainTimeoutWebSocket);
				tryAgainTimeoutWebSocket = setTimeout(verifyDesktopClientInstallation, timeoutDefault);
			}
		}

		function callbackError(event) {
			if (event.error !== undefined) {
				if (event.error !== null && event.error !== 'null') {
					console.error({ message: event.error });
				} else {
					console.error({ message: 'Unknown error' });
				}
			}
		}

		function showStatusOn() {
			$serverStatus.hide();
			$serverStatus.filter('.js-server-status-on').show();
		}

		function showStatusOff() {
			$serverStatus.hide();
			$serverStatus.filter('.js-server-status-off').show();
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
				params.afterSign && params.afterSign(response);
			})
			.error(function (error) {
				console.debug('Error:', error);
				params.onError && params.onError(error);
				params.afterSign && params.afterSign(error);
			});


		function noop() { }
	}

	function initApp() {
		// handle forms
		$('form#form-exemplo-1').submit(signFile);
		$('form#form-exemplo-2').submit(signHash);
		$('form#form-exemplo-3').submit(signText);

		// ---------- Sign FILE ----------
		function signFile(event) {
			event.preventDefault();

			var $details = $('#example-file details');
			$details.hide();

			sign({
				type: 'file',
				data: null,
				onSuccess: onSuccessFileHandler,
				onError: function (error) { printError($details, error) }, // optional
				// onCancel: onCancelHandler, // optional
				// beforeSign: beforeSignHandler, // optional
				// afterSign: afterSignHandler // optional
			});

			function onSuccessFileHandler(data) {
				printDetails($details, data);
			}
		}

		// ---------- Sign HASH ----------
		function signHash(event) {
			event.preventDefault();

			var $details = $('#example-hash details');
			$details.hide();

			var hashData = $(event.target).serializeArray().reduce(function (obj, item) {
				return item.value;
			}, {});
			sign({
				type: 'hash',
				data: hashData,
				onSuccess: onSuccessHashHandler,
				onError: function (error) { printError($details, error) }, // optional
				// onCancel: onCancelHandler, // optional
				// beforeSign: beforeSignHandler, // optional
				// afterSign: afterSignHandler // optional
			});

			function onSuccessHashHandler(data) {
				printDetails($details, data);
			}
		}

		// ---------- Sign TEXT ----------
		function signText(event) {
			event.preventDefault();
			var $details = $('#example-text details');
			$details.hide();

			var textData = $(event.target).serializeArray().reduce(function (obj, item) {
				return item.value;
			}, {});
			sign({
				type: 'text',
				data: textData,
				onSuccess: onSuccessTextHandler,
				onError: function (error) { printError($details, error) }, // optional
				// onCancel: onCancelHandler, // optional
				// beforeSign: beforeSignHandler, // optional
				// afterSign: afterSignHandler // optional
			});

			function onSuccessTextHandler(data) {
				printDetails($details, data);
			}
		}

		function printDetails($el, data) {
			var $content = $el.find('textarea');
			var signature = data.signature;
			var result = [
				'Tamanho:' + signature.size,
				'Base64:' + signature.base64
			].join('\n');
			$content.text(result);
			$el.show();
		}

		function printError($el, error) {
			var $content = $el.find('textarea');
			var result = error.error;
			$content.text(result);
			$el.show();
		}
	}

	function checkEnvironment() {
		var env = {};
		// Browser
		env.ie = is.ie();
		env.edge = is.edge();
		env.chrome = is.chrome();
		env.firefox = is.firefox();
		env.opera = is.opera();
		env.safari = is.safari();

		// OS
		env.windows = is.windows();
		env.mac = is.mac();
		env.linux = is.linux();

		// Type
		env.desktop = is.desktop();
		env.mbile = is.mobile();
		env.blackberry = is.blackberry();

		// hide all
		$('.js-is-system > *').hide();
		$('.js-is-browser > *').hide();
		for (var key in env) {
			var value = env[key];
			if (value === true) {
				$('.js-is-' + key).show();
			}
		}
	}

})();
