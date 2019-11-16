FROM fedora:30
RUN dnf install -y git vim iproute python3 pipenv bcc bpftrace && dnf clean all
ADD ./ /ipftrace/
ENV PYTHONUNBUFFERED=1
RUN cd /ipftrace && pip3 install -e .
ENTRYPOINT ["ipftrace"]
