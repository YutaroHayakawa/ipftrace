FROM fedora:30
RUN dnf install -y git vim python3 pipenv bcc bpftrace && dnf clean all
RUN git clone https://github.com/YutaroHayakawa/ipftrace.git
RUN cd /ipftrace && pip3 install -r requirements.txt
ENTRYPOINT ["/sbin/init"]
