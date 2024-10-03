/*
 * Copyright 2023-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.data.mongodb.core.encryption;

import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ClientEncryptionSettings;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoNamespace;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.model.vault.DataKeyOptions;
import com.mongodb.client.vault.ClientEncryption;
import com.mongodb.client.vault.ClientEncryptions;
import org.assertj.core.api.Assertions;
import org.bson.BsonBinary;
import org.bson.Document;
import org.bson.types.Binary;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.data.convert.PropertyValueConverterFactory;
import org.springframework.data.mongodb.config.AbstractMongoClientConfiguration;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.aggregation.Aggregation;
import org.springframework.data.mongodb.core.aggregation.AggregationResults;
import org.springframework.data.mongodb.core.convert.MongoCustomConversions.MongoConverterConfigurationAdapter;
import org.springframework.data.mongodb.core.convert.encryption.MongoEncryptionConverter;
import org.springframework.data.mongodb.core.mapping.ExplicitEncrypted;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.data.mongodb.test.util.EnableIfReplicaSetAvailable;
import org.springframework.data.mongodb.test.util.MongoClientExtension;
import org.springframework.data.util.Lazy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.Month;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.data.mongodb.core.EncryptionAlgorithms.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic;
import static org.springframework.data.mongodb.core.EncryptionAlgorithms.AEAD_AES_256_CBC_HMAC_SHA_512_Random;
import static org.springframework.data.mongodb.core.aggregation.Aggregation.newAggregation;
import static org.springframework.data.mongodb.core.query.Criteria.where;

/**
 * @author Ross Lawley
 */
@ExtendWith(MongoClientExtension.class)
@EnableIfReplicaSetAvailable
@ContextConfiguration(classes = RangeEncryptionTest.EncryptionConfig.class)
public class RangeEncryptionTest {

	@Autowired MongoTemplate template;
    // TODO
	/*

	Todo:

- [X] Add {{encryptedFields}} suppoort to {{CreateCollectionOptions}}
- [ ] Add {{contentionFactor}} to {{EncryptOptions}}
- [ ] Add {{queryType}} to {{EncryptOptions}}
- [ ] Add {{RangeOptions}} to {{EncryptOptions}}
- [ ] Add {{rangeOptions}} (String / JSON) to {{ExplicitEncrypted}} annotation
- [ ] Add {{Range}} and {{Indexed}} to encryption algorithms.
- [ ] Add {{encryptExpression}} support to {{EncryptingConverter}}
- [ ] Add test cases from the [Test Plan

		Test Plan

		Setup:
		  - Create a POJO with the valid range bson data types, annotate the fields with @ExplicitEncrypted.
		  - Insert test data
		  - Validate the data has been encrypted in the db.

		Single range tests:
		  - Perform a Range query for each of the encrypted fields
		  - Validate the expected POJO(s) is turned

		Multiple field range tests:
		  - Perform a Range query on multiple the encrypted fields at once
		  - Validate the expected POJO(s) is turned

		Multiple field tests:
		  - Perform a Range query on an encrypted fields as well as a non encrypted field
		  - Validate the expected POJO(s) is turned
	 */

	@Test
	void canEqualityMatchRangeEncryptedField() {

		Person source = new Person();
		source.id = "id-1";
		source.ssn = "mySecretSSN";

		template.save(source);

		Person loaded = template.query(Person.class).matching(where("ssn").is(source.ssn)).firstValue();
		assertThat(loaded).isEqualTo(source);
	}

	@Test
	void updateSimpleTypeEncryptedFieldWithNewValue() {

		Person source = new Person();
		source.id = "id-1";

		template.save(source);

		template.update(Person.class).matching(where("id").is(source.id)).apply(Update.update("ssn", "secret-value"))
				.first();

		verifyThat(source) //
				.identifiedBy(Person::getId) //
				.wasSavedMatching(it -> assertThat(it.get("ssn")).isInstanceOf(Binary.class)) //
				.loadedMatches(it -> assertThat(it.getSsn()).isEqualTo("secret-value"));
	}

	@Test
	void aggregationWithMatch() {

		Person person = new Person();
		person.id = "id-1";
		person.name = "p1-name";
		person.ssn = "mySecretSSN";

		template.save(person);

		AggregationResults<Person> aggregationResults = template.aggregateAndReturn(Person.class)
				.by(newAggregation(Person.class, Aggregation.match(where("ssn").is(person.ssn)))).all();
		assertThat(aggregationResults.getMappedResults()).containsExactly(person);
	}


	<T> SaveAndLoadAssert<T> verifyThat(T source) {
		return new SaveAndLoadAssert<>(source);
	}

	class SaveAndLoadAssert<T> {

		T source;
		Function<T, ?> idProvider;

		SaveAndLoadAssert(T source) {
			this.source = source;
		}

		SaveAndLoadAssert<T> identifiedBy(Function<T, ?> idProvider) {
			this.idProvider = idProvider;
			return this;
		}

		SaveAndLoadAssert<T> wasSavedAs(Document expected) {
			return wasSavedMatching(it -> Assertions.assertThat(it).isEqualTo(expected));
		}

		SaveAndLoadAssert<T> wasSavedMatching(Consumer<Document> saved) {
			RangeEncryptionTest.this.assertSaved(source, idProvider, saved);
			return this;
		}

		SaveAndLoadAssert<T> loadedMatches(Consumer<T> expected) {
			RangeEncryptionTest.this.assertLoaded(source, idProvider, expected);
			return this;
		}

		SaveAndLoadAssert<T> loadedIsEqualToSource() {
			return loadedIsEqualTo(source);
		}

		SaveAndLoadAssert<T> loadedIsEqualTo(T expected) {
			return loadedMatches(it -> Assertions.assertThat(it).isEqualTo(expected));
		}

	}

	<T> void assertSaved(T source, Function<T, ?> idProvider, Consumer<Document> dbValue) {

		Document savedDocument = template.execute(Person.class, collection -> {

			MongoNamespace namespace = collection.getNamespace();

			try (MongoClient rawClient = MongoClients.create()) {
				return rawClient.getDatabase(namespace.getDatabaseName()).getCollection(namespace.getCollectionName())
						.find(new Document("_id", idProvider.apply(source))).first();
			}
		});
		dbValue.accept(savedDocument);
	}

	<T> void assertLoaded(T source, Function<T, ?> idProvider, Consumer<T> loadedValue) {

		T loaded = template.query((Class<T>) source.getClass()).matching(where("id").is(idProvider.apply(source)))
				.firstValue();

		loadedValue.accept(loaded);
	}

	protected static class  EncryptionConfig extends AbstractMongoClientConfiguration {

		@Autowired ApplicationContext applicationContext;

		@Override
		protected String getDatabaseName() {
			return "qe-test";
		}

		@Bean
		public MongoClient mongoClient() {
			return super.mongoClient();
		}

		@Override
		protected void configureClientSettings(MongoClientSettings.Builder builder) {
			try (MongoClient mongoClient = MongoClients.create()) {
				ClientEncryptionSettings clientEncryptionSettings = encryptionSettings(mongoClient);

				builder.autoEncryptionSettings(AutoEncryptionSettings.builder() //
						.kmsProviders(clientEncryptionSettings.getKmsProviders()) //
						.keyVaultNamespace(clientEncryptionSettings.getKeyVaultNamespace()) //
						.bypassAutoEncryption(true).build());
			}
		}

		@Override
		protected void configureConverters(MongoConverterConfigurationAdapter converterConfigurationAdapter) {

			converterConfigurationAdapter
					.registerPropertyValueConverterFactory(PropertyValueConverterFactory.beanFactoryAware(applicationContext))
					.useNativeDriverJavaTimeCodecs();
		}

		@Bean
		MongoEncryptionConverter encryptingConverter(MongoClientEncryption mongoClientEncryption) {

			Lazy<BsonBinary> dataKey = Lazy.of(() -> mongoClientEncryption.getClientEncryption().createDataKey("local",
					new DataKeyOptions().keyAltNames(Collections.singletonList("mySuperSecretKey"))));

			return new MongoEncryptionConverter(mongoClientEncryption,
					EncryptionKeyResolver.annotated((ctx) -> EncryptionKey.keyId(dataKey.get())));
		}

		@Bean
		CachingMongoClientEncryption clientEncryption(ClientEncryptionSettings encryptionSettings) {
			return new CachingMongoClientEncryption(() -> ClientEncryptions.create(encryptionSettings));
		}

		@Bean
		ClientEncryptionSettings encryptionSettings(MongoClient mongoClient) {

			MongoNamespace keyVaultNamespace = new MongoNamespace("encryption.testKeyVault");
			MongoCollection<Document> keyVaultCollection = mongoClient.getDatabase(keyVaultNamespace.getDatabaseName())
					.getCollection(keyVaultNamespace.getCollectionName());
			keyVaultCollection.drop();
			// Ensure that two data keys cannot share the same keyAltName.
			keyVaultCollection.createIndex(Indexes.ascending("keyAltNames"),
					new IndexOptions().unique(true).partialFilterExpression(Filters.exists("keyAltNames")));

			MongoCollection<Document> collection = mongoClient.getDatabase(getDatabaseName()).getCollection("test");
			collection.drop(); // Clear old data

			byte[] localMasterKey = new byte[96];
			new SecureRandom().nextBytes(localMasterKey);
			Map<String, Map<String, Object>> kmsProviders = Map.of("local", Map.of("key", localMasterKey));

			// Create the ClientEncryption instance
			return ClientEncryptionSettings.builder() //
					.keyVaultMongoClientSettings(
							MongoClientSettings.builder().applyConnectionString(new ConnectionString("mongodb://localhost")).build()) //
					.keyVaultNamespace(keyVaultNamespace.getFullName()) //
					.kmsProviders(kmsProviders) //
					.build();
		}
	}

	static class CachingMongoClientEncryption extends MongoClientEncryption implements DisposableBean {

		static final AtomicReference<ClientEncryption> cache = new AtomicReference<>();

		CachingMongoClientEncryption(Supplier<ClientEncryption> source) {
			super(() -> {

				if (cache.get() != null) {
					return cache.get();
				}

				ClientEncryption clientEncryption = source.get();
				cache.set(clientEncryption);

				return clientEncryption;
			});
		}

		@Override
		public void destroy() {

			ClientEncryption clientEncryption = cache.get();
			if (clientEncryption != null) {
				clientEncryption.close();
				cache.set(null);
			}
		}
	}

	@org.springframework.data.mongodb.core.mapping.Document("test")
	static class Person {

		String id;
		String name;

		@ExplicitEncrypted(algorithm = AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic) //
		String ssn;

		@ExplicitEncrypted(algorithm = AEAD_AES_256_CBC_HMAC_SHA_512_Random, keyAltName = "mySuperSecretKey") //
		String wallet;

		@ExplicitEncrypted(algorithm = AEAD_AES_256_CBC_HMAC_SHA_512_Random) // full document must be random
		Address address;

		AddressWithEncryptedZip encryptedZip;

		@ExplicitEncrypted(algorithm = AEAD_AES_256_CBC_HMAC_SHA_512_Random) // lists must be random
		List<String> listOfString;

		@ExplicitEncrypted(algorithm = AEAD_AES_256_CBC_HMAC_SHA_512_Random) // lists must be random
		List<Address> listOfComplex;

		@ExplicitEncrypted(algorithm = AEAD_AES_256_CBC_HMAC_SHA_512_Random, keyAltName = "/name") //
		String viaAltKeyNameField;

		@ExplicitEncrypted(algorithm = AEAD_AES_256_CBC_HMAC_SHA_512_Random) //
		Map<String, String> mapOfString;

		@ExplicitEncrypted(algorithm = AEAD_AES_256_CBC_HMAC_SHA_512_Random) //
		Map<String, Address> mapOfComplex;

		@ExplicitEncrypted(algorithm = AEAD_AES_256_CBC_HMAC_SHA_512_Random) //
		LocalDate today;

		public String getId() {
			return this.id;
		}

		public String getName() {
			return this.name;
		}

		public String getSsn() {
			return this.ssn;
		}

		public String getWallet() {
			return this.wallet;
		}

		public Address getAddress() {
			return this.address;
		}

		public AddressWithEncryptedZip getEncryptedZip() {
			return this.encryptedZip;
		}

		public List<String> getListOfString() {
			return this.listOfString;
		}

		public List<Address> getListOfComplex() {
			return this.listOfComplex;
		}

		public String getViaAltKeyNameField() {
			return this.viaAltKeyNameField;
		}

		public Map<String, String> getMapOfString() {
			return this.mapOfString;
		}

		public Map<String, Address> getMapOfComplex() {
			return this.mapOfComplex;
		}

		public LocalDate getToday() {
			return today;
		}

		public void setId(String id) {
			this.id = id;
		}

		public void setName(String name) {
			this.name = name;
		}

		public void setSsn(String ssn) {
			this.ssn = ssn;
		}

		public void setWallet(String wallet) {
			this.wallet = wallet;
		}

		public void setAddress(Address address) {
			this.address = address;
		}

		public void setEncryptedZip(AddressWithEncryptedZip encryptedZip) {
			this.encryptedZip = encryptedZip;
		}

		public void setListOfString(List<String> listOfString) {
			this.listOfString = listOfString;
		}

		public void setListOfComplex(List<Address> listOfComplex) {
			this.listOfComplex = listOfComplex;
		}

		public void setViaAltKeyNameField(String viaAltKeyNameField) {
			this.viaAltKeyNameField = viaAltKeyNameField;
		}

		public void setMapOfString(Map<String, String> mapOfString) {
			this.mapOfString = mapOfString;
		}

		public void setMapOfComplex(Map<String, Address> mapOfComplex) {
			this.mapOfComplex = mapOfComplex;
		}

		public void setToday(LocalDate today) {
			this.today = today;
		}

		@Override
		public boolean equals(Object o) {
			if (o == this) {
				return true;
			}
			if (o == null || getClass() != o.getClass()) {
				return false;
			}
			Person person = (Person) o;
			return Objects.equals(id, person.id) && Objects.equals(name, person.name) && Objects.equals(ssn, person.ssn)
					&& Objects.equals(wallet, person.wallet) && Objects.equals(address, person.address)
					&& Objects.equals(encryptedZip, person.encryptedZip) && Objects.equals(listOfString, person.listOfString)
					&& Objects.equals(listOfComplex, person.listOfComplex)
					&& Objects.equals(viaAltKeyNameField, person.viaAltKeyNameField)
					&& Objects.equals(mapOfString, person.mapOfString) && Objects.equals(mapOfComplex, person.mapOfComplex)
					&& Objects.equals(today, person.today);
		}

		@Override
		public int hashCode() {
			return Objects.hash(id, name, ssn, wallet, address, encryptedZip, listOfString, listOfComplex, viaAltKeyNameField,
					mapOfString, mapOfComplex, today);
		}

		public String toString() {
			return "EncryptionTests.Person(id=" + this.getId() + ", name=" + this.getName() + ", ssn=" + this.getSsn()
					+ ", wallet=" + this.getWallet() + ", address=" + this.getAddress() + ", encryptedZip="
					+ this.getEncryptedZip() + ", listOfString=" + this.getListOfString() + ", listOfComplex="
					+ this.getListOfComplex() + ", viaAltKeyNameField=" + this.getViaAltKeyNameField() + ", mapOfString="
					+ this.getMapOfString() + ", mapOfComplex=" + this.getMapOfComplex() + ", today=" + this.getToday() + ")";
		}
	}

	static class Address {
		String city;
		String street;

		public Address() {}

		public String getCity() {
			return this.city;
		}

		public String getStreet() {
			return this.street;
		}

		public void setCity(String city) {
			this.city = city;
		}

		public void setStreet(String street) {
			this.street = street;
		}

		@Override
		public boolean equals(Object o) {
			if (o == this) {
				return true;
			}
			if (o == null || getClass() != o.getClass()) {
				return false;
			}
			Address address = (Address) o;
			return Objects.equals(city, address.city) && Objects.equals(street, address.street);
		}

		@Override
		public int hashCode() {
			return Objects.hash(city, street);
		}

		public String toString() {
			return "EncryptionTests.Address(city=" + this.getCity() + ", street=" + this.getStreet() + ")";
		}
	}

	static class AddressWithEncryptedZip extends Address {

		@ExplicitEncrypted(algorithm = AEAD_AES_256_CBC_HMAC_SHA_512_Random) String zip;

		@Override
		public String toString() {
			return "AddressWithEncryptedZip{" + "zip='" + zip + '\'' + ", city='" + getCity() + '\'' + ", street='"
					+ getStreet() + '\'' + '}';
		}

		public String getZip() {
			return this.zip;
		}

		public void setZip(String zip) {
			this.zip = zip;
		}
	}
}
