SET FOREIGN_KEY_CHECKS = 0;
drop table if exists acl_sid;
create table acl_sid (
  id bigint not null primary key auto_increment,
  principal boolean not null,
  sid varchar(100) not null,
  constraint unique_uk_1 unique(sid,principal) );

drop table if exists acl_sid_include;
create table acl_sid_include (
  id bigint not null primary key auto_increment,
  higher bigint not null,
  lower bigint not null,
  constraint acl_sid_include_fk_higher foreign key(higher)references acl_sid(id),
  constraint acl_sid_include_fk_lower foreign key(lower)references acl_sid(id),
  constraint acl_sid_include_uk unique(higher,lower) );

drop table if exists acl_class;
create table acl_class (
  id bigint not null primary key auto_increment,
  class varchar(100) not null,
  constraint unique_uk_2 unique(class) );

drop table if exists acl_object_identity;
create table acl_object_identity (
  id bigint not null primary key auto_increment,
  object_id_class bigint not null,
  object_id_identity bigint not null,
  parent_object bigint,
  owner_sid bigint not null,
  entries_inheriting boolean not null,
  constraint unique_uk_3 unique(object_id_class,object_id_identity),
  constraint foreign_fk_1 foreign key(parent_object)references acl_object_identity(id),
  constraint foreign_fk_2 foreign key(object_id_class)references acl_class(id),
  constraint foreign_fk_3 foreign key(owner_sid)references acl_sid(id) );

drop table if exists acl_entry;
create table acl_entry (
  id bigint not null primary key auto_increment,
  acl_object_identity bigint not null,
  ace_order int not null,
  sid bigint not null,
  mask integer not null,
  granting boolean not null,
  start timestamp,
  end timestamp,
  audit_success boolean not null,
  audit_failure boolean not null,
  constraint unique_uk_4 unique(acl_object_identity,ace_order),
  constraint foreign_fk_4 foreign key(acl_object_identity)
      references acl_object_identity(id),
  constraint foreign_fk_5 foreign key(sid) references acl_sid(id) );

drop table if exists users;
create table users (
  username varchar(255) not null primary key,
  password varchar(255) not null,
  enabled boolean default true );

drop table if exists authorities;
create table authorities (
  username varchar(255) not null,
  authority varchar(255) not null,
  constraint authorities_fk foreign key(username)references users(username),
  constraint authorities_uk unique(username,authority) );

drop table if exists groups;
create table groups (
  id bigint not null primary key auto_increment,
  group_name varchar(50) not null);

drop table if exists group_authorities;
create table group_authorities (
  group_id bigint not null,
  authority varchar(50) not null,
  constraint fk_group_authorities_group foreign key(group_id) references groups(id));

drop table if exists group_members;
create table group_members (
  id bigint not null primary key auto_increment,
  username varchar(50) not null,
  group_id bigint not null,
  constraint fk_group_members_group foreign key(group_id) references groups(id));

drop table if exists persistent_logins;
create table persistent_logins (
  username varchar(64) not null,
  series varchar(64) primary key,
  token varchar(64) not null,
  last_used timestamp not null);

INSERT INTO `acl_sid` VALUES ('2', '0', 'ROLE_ADMIN'), ('1', '0', 'ROLE_USER');
INSERT INTO `acl_sid_include` VALUES ('1', '2', '1');
INSERT INTO `users` VALUES ('bob', 'bob', '1');
INSERT INTO `authorities` VALUES ('bob', 'ROLE_ADMIN');

INSERT INTO `acl_class` VALUES ('1', 'com.datayes.paas.Foo');
INSERT INTO `acl_entry` VALUES ('1', '1', '0', '1', '1', '1', '2013-11-07 10:48:22', '2014-11-07 10:48:42', '0', '0');
INSERT INTO `acl_entry` VALUES ('2', '1', '1', '1', '2', '1', '2013-11-07 10:48:22', '2014-11-07 10:48:42', '0', '0');
INSERT INTO `acl_object_identity` VALUES ('1', '1', '1', null, '1', '1');

set FOREIGN_KEY_CHECKS = 1;