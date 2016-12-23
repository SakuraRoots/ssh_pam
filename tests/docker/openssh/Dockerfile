FROM alpine

RUN apk add --update openssh && \
 adduser -D user -h /data/ && \
 echo user:user | chpasswd && \
 rm -rf /tmp/* /var/cache/apk/* /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_dsa_key

ADD config/docker-entrypoint.sh /usr/sbin
EXPOSE 22

ENTRYPOINT ["/usr/sbin/docker-entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D"]