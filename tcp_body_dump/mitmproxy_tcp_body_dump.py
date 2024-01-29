from mitmproxy import tcp
import base64
from datetime import datetime
current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

outfile = "tcp_body_dump_"+str(current_datetime)+".txt"

def tcp_message(flow: tcp.TCPFlow):
    message = flow.messages[-1]
    with open(outfile, "ab") as ofile:
        if message.from_client:
            ofile.write(b"c;")
        else:
            ofile.write(b"s;")
        ofile.write(base64.b64encode(message.content))
        ofile.write(b"\r\n")
