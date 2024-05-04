function get_connect_info() {
    var host = $.trim($('#host').val());
    var port = $.trim($('#port').val());
    var user = $.trim($('#user').val());
    var auth = $("input[name='auth']:checked").val();
    var pwd = $.trim($('#password').val());
    var password = window.btoa(pwd);
    var ssh_key = null;

    if (auth === 'key') {
        var pkey = $('#pkey')[0].files[0];
        var csrf = $("[name='csrfmiddlewaretoken']").val();
        var formData = new FormData();

        formData.append('pkey', pkey);
        formData.append('csrfmiddlewaretoken', csrf);

        $.ajax({
            url: '/upload_ssh_key/',
            type: 'post',
            data: formData,
            async: false,
            processData: false,
            contentType: false,
            mimeType: 'multipart/form-data',
            success: function (data) {
                ssh_key = data;
            }
        });
    }

    var connect_info1 = 'host=' + host + '&port=' + port + '&user=' + user + '&auth=' + auth;
    var connect_info2 = '&password=' + password + '&ssh_key=' + ssh_key;
    var connect_info = connect_info1 + connect_info2;
    return connect_info
}


function get_term_size() {
    var init_width = 9;
    var init_height = 18;

    var windows_width = $(window).width();
    var windows_height = $(window).height();

    return {
        cols: Math.floor(windows_width / init_width),
        rows: Math.floor(windows_height / init_height),
    }
}

function websocket() {
    var cols = get_term_size().cols;
    var rows = get_term_size().rows;
    var connect_info = get_connect_info();

    var term = new Terminal(
        {
            cols: cols,
            rows: rows,
            useStyle: true,
            cursorBlink: true
        }
        ),
        protocol = (location.protocol === 'https:') ? 'wss://' : 'ws://',
        socketURL = protocol + location.hostname + ((location.port) ? (':' + location.port) : '') +
            '/ws/webssh/?' + connect_info + '&width=' + cols + '&height=' + rows;

    var sock;
    sock = new WebSocket(socketURL);
    sock.binaryType = "arraybuffer";    // Phải được đặt trước khi có thể sử dụng zmodem

    function uploadFile(zsession) {
        let uploadHtml = "<div>" +
            "<label class='upload-area' style='width:100%;text-align:center;' for='fupload'>" +
            "<input id='fupload' name='fupload' type='file' style='display:none;' multiple='true'>" +
            "<i class='fa fa-cloud-upload fa-3x'></i>" +
            "<br />" +
            "Bấm để chọn tập tin" +
            "</label>" +
            "<br />" +
            "<span style='margin-left:5px !important;' id='fileList'></span>" +
            "</div><div class='clearfix'></div>";

        let upload_dialog = bootbox.dialog({
            message: uploadHtml,
            title: "tải tập tin lên",
            buttons: {
				cancel: {
					label: 'Khép kín',
					className: 'btn-default',
					callback: function (res) {
						try {
							// zsession gửi một gói ZACK cứ sau 5 giây, sau 5 giây sẽ xuất hiện thông báo rằng gói cuối cùng là "ZACK" và không thể đóng bình thường
							// Ở đây, đặt trực tiếp _last_header_name thành ZRINIT, sau đó có thể buộc phải đóng
							zsession._last_header_name = "ZRINIT";
							zsession.close();
						} catch (e) {
							console.log(e);
						}
					}
				},
            },
			closeButton: false,
        });

        function hideModal() {
			upload_dialog.modal('hide');
		}

		let file_el = document.getElementById("fupload");

		return new Promise((res) => {
			file_el.onchange = function (e) {
				let files_obj = file_el.files;
				hideModal();
				Zmodem.Browser.send_files(zsession, files_obj, {
						on_offer_response(obj, xfer) {
							if (xfer) {
								// term.write("\r\n");
							} else {
								// term.write("\r\n" + obj.name + " was upload skipped");
								term.write(obj.name + " was upload skipped\r\n");
								//socket.send(JSON.stringify({ type: "ignore", data: utoa("\r\n" + obj.name + " was upload skipped\r\n") }));
							}
						},
						on_progress(obj, xfer) {
							updateProgress(xfer);
						},
						on_file_complete(obj) {
							//socket.send(JSON.stringify({ type: "ignore", data: utoa("\r\n" + obj.name + " was upload success\r\n") }));
							// console.log("COMPLETE", obj);
                            term.write("\r\n");
						},
					}
				).then(zsession.close.bind(zsession), console.error.bind(console)
				).then(() => {
					res();
					// term.write("\r\n");
				});
			};
		});
    }

	function saveFile(xfer, buffer) {
		return Zmodem.Browser.save_to_disk(buffer, xfer.get_details().name);
	}

	function updateProgress(xfer) {
		let detail = xfer.get_details();
		let name = detail.name;
		let total = detail.size;
		let percent;
		if (total === 0) {
			percent = 100
		} else {
			percent = Math.round(xfer._file_offset / total * 100);
		}

		term.write("\r" + name + ": " + total + " " + xfer._file_offset + " " + percent + "%    ");
	}

	function downloadFile(zsession) {
		zsession.on("offer", function(xfer) {
			function on_form_submit() {
				let FILE_BUFFER = [];
				xfer.on("input", (payload) => {
					updateProgress(xfer);
					FILE_BUFFER.push( new Uint8Array(payload) );
				});

				xfer.accept().then(
					() => {
						saveFile(xfer, FILE_BUFFER);
						term.write("\r\n");
						//socket.send(JSON.stringify({ type: "ignore", data: utoa("\r\n" + xfer.get_details().name + " was download success\r\n") }));
					},
					console.error.bind(console)
				);
			}

			on_form_submit();

		});

		let promise = new Promise( (res) => {
			zsession.on("session_end", () => {
				res();
			});
		});

		zsession.start();
		return promise;
	}

     var zsentry = new Zmodem.Sentry( {
        to_terminal: function(octets) {},  //i.e. send to the terminal

        on_detect: function(detection) {
            let zsession = detection.confirm();
            let promise;
            if (zsession.type === "receive") {
                promise = downloadFile(zsession);
            } else {
                promise = uploadFile(zsession);
            }
            promise.catch( console.error.bind(console) ).then( () => {
                //
            });
        },

        on_retract: function() {},

        sender: function(octets) { sock.send(new Uint8Array(octets)) },
     });

    //
    // Để mở kết nối websocket, hãy mở thiết bị đầu cuối web
    sock.addEventListener('open', function () {
        $('#form').addClass('hide');
        $('#django-webssh-terminal').removeClass('hide');
        term.open(document.getElementById('terminal'));
		term.focus();
		$("body").attr("onbeforeunload",'checkwindow()');//Tăng thuộc tính dấu nhắc đóng refresh

    });

    // Đọc dữ liệu được gửi bởi máy chủ và ghi nó vào thiết bị đầu cuối web
    sock.addEventListener('message', function (recv) {
        if (typeof(recv.data) === 'string') {
            var data = JSON.parse(recv.data);
            var message = data.message;
            var status = data.status;
            if (status === 0) {
                term.write(message)
            } else {
                //window.location.reload()
                // Làm mới trang sau khi cổng được kết nối
                //term.clear()
                term.write(message);
                $("body").removeAttr("onbeforeunload");//Xóa thuộc tính nhắc đóng refresh

                //$(document).keyup(function(event){	// Lắng nghe sự kiện phím Enter
                //	if(event.keyCode == 13){
                        //window.location.reload();
                //	}
                //});
                //term.dispose()
                //$('#django-webssh-terminal').addClass('hide');
                //$('#form').removeClass('hide');
            }
        } else {
		    zsentry.consume(recv.data);
        }
    });

    /*
* Khi trạng thái là 0, dữ liệu do người dùng nhập vào được truyền vào nền thông qua websocket, dữ liệu là dữ liệu được truyền và các tham số cols và rows bị bỏ qua
    * Khi status là 1, resize pty ssh terminal size, cols là số ký tự hiển thị tối đa trong mỗi hàng, rows là số ký tự hiển thị tối đa trong mỗi cột, bỏ qua tham số data
    */
    var message = {'status': 0, 'data': null, 'cols': null, 'rows': null};

    term.onData(function (data) {
        message['status'] = 0;
        message['data'] = data;
        var send_data = JSON.stringify(message);
        sock.send(send_data)
    });

    // Giám sát cửa sổ trình duyệt và sửa đổi kích thước thiết bị đầu cuối theo kích thước của cửa sổ trình duyệt
    $(window).resize(function () {
        var cols = get_term_size().cols;
        var rows = get_term_size().rows;
        message['status'] = 1;
        message['cols'] = cols;
        message['rows'] = rows;
        var send_data = JSON.stringify(message);
        sock.send(send_data);
        term.resize(cols, rows)
    })
}