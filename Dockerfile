FROM python:3.11.4-slim-bullseye as builder

WORKDIR /workspace

# 의존 패키지 설치
COPY Pipfile Pipfile.lock ./
RUN pip install pipenv
RUN pipenv install --system --deploy


FROM python:3.11.4-slim-bullseye as final

WORKDIR /workspace

# Chrome 설치
RUN apt-get update && apt-get install -y wget
RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN dpkg -i ./google-chrome-stable_current_amd64.deb || (apt-get -f install -y && dpkg -i ./google-chrome-stable_current_amd64.deb)
RUN rm ./google-chrome-stable_current_amd64.deb

# Python 패키지 복사
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/

# 애플리케이션 코드 복사
COPY . ./

ENV PYTHONPATH /workspace:$PYTHONPATH

CMD ["python", "app/__main__.py"]
