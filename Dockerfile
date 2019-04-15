FROM python:3

ADD https://github.com/cloudfoundry/bosh-cli/releases/download/v5.4.0/bosh-cli-5.4.0-linux-amd64 /usr/bin/bosh
ADD ["https://cli.run.pivotal.io/stable?release=debian64&source=github", "/tmp/cf-cli.deb"]

RUN dpkg -i /tmp/cf-cli.deb \
    && apt-get install -f \
    && rm /tmp/cf-cli.deb \
    && apt-get update && apt-get install -y \
        git \
        vim \
        nano \
        bash \
        build-essential \
        zlibc \
        zlib1g-dev \
        ruby \
        ruby-dev \
        openssl \
        libxslt-dev \
        libxml2-dev \
        libssl-dev \
        libreadline7 \
        libreadline-dev \
        libyaml-dev \
        libsqlite3-dev \
        sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && chmod +x /usr/bin/bosh

COPY . /monarch
WORKDIR /monarch

RUN pip install --no-cache-dir -r requirements.txt \
    && python setup.py install \
    && rm -rf monarch.egg-info .eggs

VOLUME ["/monarch/config", "/monarch/tests/config"]
ENTRYPOINT ["bash"]
