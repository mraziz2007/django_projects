FROM python

EXPOSE 8889

ADD . /ad_app
WORKDIR /ad_app

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

RUN pip install pycryptodome --break-system-packages

RUN ls -la

ENTRYPOINT ["python", "manage.py"]

CMD [ "runserver", "0.0.0.0:8889" ] 