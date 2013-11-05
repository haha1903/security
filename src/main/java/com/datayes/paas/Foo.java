package com.datayes.paas;

/**
 * Created by changhai on 13-10-28.
 */
public class Foo {
    private long id;
    private long type;
    private long value;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public long getType() {
        return type;
    }

    public void setType(long type) {
        this.type = type;
    }

    public long getValue() {
        return value;
    }

    public void setValue(long value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return "Foo{" +
                "id=" + id +
                ", type=" + type +
                ", value=" + value +
                '}';
    }
}
