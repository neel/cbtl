-- Role: cbtl_user

DROP ROLE IF EXISTS cbtl_user;

CREATE ROLE cbtl_user WITH LOGIN NOSUPERUSER INHERIT NOCREATEROLE;

-- Database: cbtlr

DROP DATABASE IF EXISTS cbtl;

CREATE DATABASE cbtl WITH OWNER cbtl_user;


-- Table: public.persons

DROP TABLE IF EXISTS public.persons;

CREATE TABLE IF NOT EXISTS public.persons
(
    y bytea NOT NULL,
    random bytea NOT NULL,
    name text COLLATE pg_catalog."default" NOT NULL,
    age integer NOT NULL,
    CONSTRAINT persons_pkey PRIMARY KEY (y)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.persons OWNER to cbtl_user;

-- Table: public.records

DROP TABLE IF EXISTS public.records;

CREATE TABLE IF NOT EXISTS public.records
(
    anchor text COLLATE pg_catalog."default" NOT NULL,
    hint bytea NOT NULL,
    random bytea NOT NULL,
    created timestamp without time zone NOT NULL DEFAULT now(),
    "case" text COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT records_pkey PRIMARY KEY (anchor)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.records OWNER to cbtl_user;
