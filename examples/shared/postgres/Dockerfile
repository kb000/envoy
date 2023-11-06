FROM postgres:latest@sha256:a80d0c1b119cf3d6bab27f72782f16e47ab8534ced937fa813ec2ab26e1fd81e
COPY docker-healthcheck.sh /usr/local/bin/
HEALTHCHECK CMD ["docker-healthcheck.sh"]
