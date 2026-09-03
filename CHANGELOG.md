# Changelog

All notable changes to PSADDS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the module follows
[semantic versioning](https://semver.org/).

## [0.4.0] - 2026-09-03

### Added

- `Set-ADSchemaAttributeConfidential`: marks a schema attribute as confidential (bit 128 of `searchFlags`), or
  removes the mark. Validates first that the bit will actually be honoured: base schema attributes
  (`systemFlags` 0x10) and constructed attributes (`systemFlags` 0x4) are refused, since the bit is stored and
  ignored on those, which is worse than not setting it. Writes on the schema master by default, preserves the
  other `searchFlags` bits, and supports `-WhatIf`.

## [0.3.1] - 2026-09-02

### Added

- `Get-ADUserPasswordInfo`: password state of the users, with the policy that actually applies to each of them,
  the default domain policy or the Fine Grained Password Policy that wins over it. `-SimulatedMaxPasswordAgeDays`
  measures the impact of a policy change before it is applied.
- `Get-ADObjectMetadata`: replication metadata of the attributes of an object, that is, which attribute changed,
  when, and on which domain controller. Answers questions that `whenChanged` cannot, long after it has been
  overwritten.
- `Get-ADGroupMembershipMetadata`: replication metadata of the members of a group, including the members that
  were removed, which remain visible until the tombstone lifetime has elapsed. Group membership is a linked
  value, carried by `msDS-ReplValueMetaData` and not by `msDS-ReplAttributeMetaData`, hence a function of its
  own: asking `Get-ADObjectMetadata` for `member` warns and points here.

### Notes

The three functions come from the
[ActiveDirectory-Toolbox](https://github.com/bastienperez/ActiveDirectory-Toolbox) repository, where they were
standalone scripts. What changed on the way:

**`Get-ADUserPasswordInfo`**

- the `Get-ADPasswordSettingsByUser` alias was dropped;
- `-DomainController` became `-Server`, kept as a parameter alias;
- `LockoutObservationWindow` returned the value of `LockoutDuration`;
- `Get-ADUserResultantPasswordPolicy` was called once per user, which dominated the runtime on a large domain.
  The domain is now checked for Fine Grained Password Policies first, and the per user call is skipped entirely
  when there is none.

**`Get-ADObjectMetadata`**

- `-DomainController` became `-Server`, kept as a parameter alias, and `-ObjectDN` is an alias of `-Identity`;
- an attribute passed to `-Attributes` that carried no metadata produced a row with every field empty. It now
  warns, and names the right function when the attribute is a linked one;
- the error paths returned `1`, which ended up in the pipeline and in any export;
- the ambiguous name resolution fallback checked `.Count` on a result that is not always an array, so two
  matching objects could go through unnoticed;
- `ObjectDN` and `FromDomainController` were added to the output, since the metadata differs from one domain
  controller to another.

**`Get-ADGroupMembershipMetadata`**

- gained `-Server`, which it did not have at all;
- the output was one object holding a nested `Members` collection, which does not export and does not filter.
  It is now one flat object per member, with `GroupDN` on each row;
- gained `IsDeleted`, `-DeletedOnly` and `-CurrentOnly`. Removed members are the reason this metadata is read
  in the first place, and they were indistinguishable in the previous output;
- entries are filtered on `member`, since `msDS-ReplValueMetaData` covers every linked attribute of the object;
- accepts pipeline input by property name, so `Get-ADGroup ... | Get-ADGroupMembershipMetadata` works.

**Both metadata functions**

- the normalization of the raw metadata, wrapping the XML fragments in a root element and stripping the null
  padding, was copy pasted in four scripts of the source repository. It is now a single private helper;
- `ftimeCreated`, `ftimeDeleted` and `ftimeLastOriginatingChange` were returned as strings, so sorting and
  comparing them were string operations, and a value that was never set was reported as `1601-01-01`, the zero
  of a Windows FILETIME. They are now `[datetime]` in UTC, or `$null` when never set.

## [0.3.0] - 2026-08-31

### Added

- `Get-ADSchemaAttribute`, `Get-ADSchemaClassAttribute`, `Get-ADSchemaClassPossibleChildren`,
  `Get-ADSchemaRelatedClass` and `Get-ADSchemaVersion`: the schema reporting functions, migrated from the
  [ActiveDirectory-Toolbox](https://github.com/bastienperez/ActiveDirectory-Toolbox) repository and grouped
  under a common `Get-ADSchema` prefix.
- `ConvertFrom-ADSearchFlags`, a private helper decoding the `searchFlags` bit field once for every function
  that reports on it.

### Changed

- the schema queries filter server side and stream their results, instead of collecting the whole schema
  partition first.

## [0.1.1]

`Get-ADComputerJoinedByUser`, `Reset-ADComputerAccountSecurity`, `Set-ADUserCommonName`.
